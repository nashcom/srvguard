// srvguard.cpp — srvguard C++ consumer implementation

#include "srvguard.hpp"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

// ExtractJsonField extracts the string value of pszField from a flat JSON
// object. Handles the simple {"key":"value",...} format written by srvguard.
// No external JSON library required — we control the format.
static bool ExtractJsonField (const char *pszJson,
                               size_t      nJsonLen,
                               const char *pszField,
                               char       *pszValue,
                               size_t      nMaxLen)
{
    if (!pszJson || !pszField || !pszValue || nMaxLen == 0)
        return false;

    // build search pattern: "field":"
    char szPattern[256] = {};
    snprintf (szPattern, sizeof (szPattern) - 1, "\"%s\":\"", pszField);

    const char *pszStart = strstr (pszJson, szPattern);
    if (!pszStart)
        return false;

    pszStart += strlen (szPattern);

    // bounds check — ensure start is within the JSON buffer
    if (pszStart >= pszJson + nJsonLen)
        return false;

    // find closing quote, respecting escaped quotes
    const char *pszEnd = pszStart;
    while (*pszEnd && *pszEnd != '"')
    {
        if (*pszEnd == '\\')
            pszEnd++; // skip escaped character
        pszEnd++;
    }

    size_t nLen = (size_t)(pszEnd - pszStart);
    if (nLen >= nMaxLen)
        nLen = nMaxLen - 1;

    memcpy (pszValue, pszStart, nLen);
    pszValue[nLen] = '\0';

    // unescape \n sequences (PEM blocks stored with literal \n)
    char *pszDst = pszValue;
    const char *pszSrc = pszValue;
    while (*pszSrc)
    {
        if (pszSrc[0] == '\\' && pszSrc[1] == 'n')
        {
            *pszDst++ = '\n';
            pszSrc += 2;
        }
        else
        {
            *pszDst++ = *pszSrc++;
        }
    }
    *pszDst = '\0';

    return true;
}

// -----------------------------------------------------------------------------
// Keyring backend (Linux only)
// -----------------------------------------------------------------------------

#ifdef __linux__

#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

// keyctl command codes
#define KEYCTL_REVOKE   3
#define KEYCTL_READ     11
#define KEYCTL_SEARCH   10

// special keyring IDs
#define KEY_SPEC_SESSION_KEYRING  ((int)-3)

static long keyctl_call (int nCmd, unsigned long nArg2, unsigned long nArg3,
                          unsigned long nArg4, unsigned long nArg5)
{
    return syscall (SYS_keyctl, nCmd, nArg2, nArg3, nArg4, nArg5);
}

bool SrvGuardKeyringRead (const char *pszLabel,
                          const char *pszField,
                          char       *pszValue,
                          size_t      nMaxLen)
{
    if (!pszLabel || !pszField || !pszValue || nMaxLen == 0)
        return false;

    // search session keyring for our key
    long nSerial = keyctl_call (KEYCTL_SEARCH,
                                (unsigned long)(long) KEY_SPEC_SESSION_KEYRING,
                                (unsigned long) "user",
                                (unsigned long) pszLabel,
                                0);
    if (nSerial < 0)
        return false;

    // probe payload size
    long nSize = keyctl_call (KEYCTL_READ, (unsigned long) nSerial, 0, 0, 0);
    if (nSize <= 0)
        return false;

    char *pszJson = (char *) malloc ((size_t) nSize + 1);
    if (!pszJson)
        return false;

    // read payload
    long nRead = keyctl_call (KEYCTL_READ,
                              (unsigned long) nSerial,
                              (unsigned long) pszJson,
                              (unsigned long) nSize,
                              0);

    bool bResult = false;

    if (nRead > 0)
    {
        pszJson[nRead] = '\0';
        bResult = ExtractJsonField (pszJson, (size_t) nRead,
                                    pszField, pszValue, nMaxLen);
    }

    // always revoke the key — one-time read
    keyctl_call (KEYCTL_REVOKE, (unsigned long) nSerial, 0, 0, 0);

    // zero the JSON buffer before freeing
    memset (pszJson, 0, (size_t) nSize);
    free (pszJson);

    return bResult;
}

#else // non-Linux stub

bool SrvGuardKeyringRead (const char * /*pszLabel*/,
                          const char * /*pszField*/,
                          char       * /*pszValue*/,
                          size_t       /*nMaxLen*/)
{
    return false; // kernel keyring only available on Linux
}

#endif // __linux__

// -----------------------------------------------------------------------------
// Files backend
// -----------------------------------------------------------------------------

bool SrvGuardFileRead (const char *pszDir,
                       const char *pszFile,
                       char       *pszValue,
                       size_t      nMaxLen)
{
    if (!pszDir || !pszFile || !pszValue || nMaxLen == 0)
        return false;

    char szPath[1024] = {};
    snprintf (szPath, sizeof (szPath) - 1, "%s/%s", pszDir, pszFile);

    FILE *pFile = fopen (szPath, "rb");
    if (!pFile)
        return false;

    size_t nRead = fread (pszValue, 1, nMaxLen - 1, pFile);
    fclose (pFile);

    pszValue[nRead] = '\0';
    return nRead > 0;
}

// -----------------------------------------------------------------------------
// Zero helper — volatile to prevent compiler optimisation
// -----------------------------------------------------------------------------

void SrvGuardZero (void *pBuf, size_t nLen)
{
    volatile char *p = (volatile char *) pBuf;
    while (nLen--)
        *p++ = 0;
}
