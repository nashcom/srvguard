// srvguard.cpp — srvguard C++ consumer implementation

#include "srvguard.hpp"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

// -----------------------------------------------------------------------------
// Minimal SHA-256 — self-contained, no external dependencies.
// Based on FIPS 180-4. Used only for keyring label derivation.
// -----------------------------------------------------------------------------

static const uint32_t c_dwShaK[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA256_ROTR(x,n)   (((x) >> (n)) | ((x) << (32-(n))))
#define SHA256_CH(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x)      (SHA256_ROTR(x,2)  ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x)      (SHA256_ROTR(x,6)  ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x)     (SHA256_ROTR(x,7)  ^ SHA256_ROTR(x,18) ^ ((x) >>  3))
#define SHA256_SIG1(x)     (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

typedef struct
{
    uint32_t dwState[8];
    uint8_t  abBuf[64];
    uint32_t dwBufLen;
    uint64_t qwTotalLen;
} SHA256_CTX;

static void Sha256Transform (uint32_t *pdwState, const uint8_t *pbData)
{
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    uint32_t m[64];
    int      i;

    for (i = 0; i < 16; i++)
        m[i] = ((uint32_t) pbData[i*4]   << 24)
              | ((uint32_t) pbData[i*4+1] << 16)
              | ((uint32_t) pbData[i*4+2] <<  8)
              |  (uint32_t) pbData[i*4+3];

    for (; i < 64; i++)
        m[i] = SHA256_SIG1(m[i-2]) + m[i-7] + SHA256_SIG0(m[i-15]) + m[i-16];

    a = pdwState[0]; b = pdwState[1]; c = pdwState[2]; d = pdwState[3];
    e = pdwState[4]; f = pdwState[5]; g = pdwState[6]; h = pdwState[7];

    for (i = 0; i < 64; i++)
    {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + c_dwShaK[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    pdwState[0] += a; pdwState[1] += b; pdwState[2] += c; pdwState[3] += d;
    pdwState[4] += e; pdwState[5] += f; pdwState[6] += g; pdwState[7] += h;
}

static void Sha256Init (SHA256_CTX *pCtx)
{
    pCtx->dwBufLen   = 0;
    pCtx->qwTotalLen = 0;
    pCtx->dwState[0] = 0x6a09e667;
    pCtx->dwState[1] = 0xbb67ae85;
    pCtx->dwState[2] = 0x3c6ef372;
    pCtx->dwState[3] = 0xa54ff53a;
    pCtx->dwState[4] = 0x510e527f;
    pCtx->dwState[5] = 0x9b05688c;
    pCtx->dwState[6] = 0x1f83d9ab;
    pCtx->dwState[7] = 0x5be0cd19;
}

static void Sha256Update (SHA256_CTX *pCtx, const uint8_t *pbData, size_t nLen)
{
    size_t i;

    for (i = 0; i < nLen; i++)
    {
        pCtx->abBuf[pCtx->dwBufLen++] = pbData[i];
        if (pCtx->dwBufLen == 64)
        {
            Sha256Transform (pCtx->dwState, pCtx->abBuf);
            pCtx->qwTotalLen += 512;
            pCtx->dwBufLen = 0;
        }
    }
}

static void Sha256Final (SHA256_CTX *pCtx, uint8_t abDigest[32])
{
    uint32_t i;
    uint64_t qwBitLen;

    i = pCtx->dwBufLen;
    pCtx->abBuf[i++] = 0x80;

    if (pCtx->dwBufLen < 56)
    {
        while (i < 56)
            pCtx->abBuf[i++] = 0x00;
    }
    else
    {
        while (i < 64)
            pCtx->abBuf[i++] = 0x00;
        Sha256Transform (pCtx->dwState, pCtx->abBuf);
        memset (pCtx->abBuf, 0, 56);
        i = 0;
    }

    pCtx->qwTotalLen += (uint64_t) pCtx->dwBufLen * 8;
    qwBitLen = pCtx->qwTotalLen;

    pCtx->abBuf[63] = (uint8_t)(qwBitLen);
    pCtx->abBuf[62] = (uint8_t)(qwBitLen >>  8);
    pCtx->abBuf[61] = (uint8_t)(qwBitLen >> 16);
    pCtx->abBuf[60] = (uint8_t)(qwBitLen >> 24);
    pCtx->abBuf[59] = (uint8_t)(qwBitLen >> 32);
    pCtx->abBuf[58] = (uint8_t)(qwBitLen >> 40);
    pCtx->abBuf[57] = (uint8_t)(qwBitLen >> 48);
    pCtx->abBuf[56] = (uint8_t)(qwBitLen >> 56);

    Sha256Transform (pCtx->dwState, pCtx->abBuf);

    for (i = 0; i < 4; i++)
    {
        abDigest[i]    = (uint8_t)(pCtx->dwState[0] >> (24 - i*8));
        abDigest[i+4]  = (uint8_t)(pCtx->dwState[1] >> (24 - i*8));
        abDigest[i+8]  = (uint8_t)(pCtx->dwState[2] >> (24 - i*8));
        abDigest[i+12] = (uint8_t)(pCtx->dwState[3] >> (24 - i*8));
        abDigest[i+16] = (uint8_t)(pCtx->dwState[4] >> (24 - i*8));
        abDigest[i+20] = (uint8_t)(pCtx->dwState[5] >> (24 - i*8));
        abDigest[i+24] = (uint8_t)(pCtx->dwState[6] >> (24 - i*8));
        abDigest[i+28] = (uint8_t)(pCtx->dwState[7] >> (24 - i*8));
    }
}

// -----------------------------------------------------------------------------
// Keyring label derivation
// -----------------------------------------------------------------------------

// Build salt baked into the binary at compile time.
// Must match keyringBuildSalt in src/keyring.go.
// Override at build time via SRVGUARD_BUILD_SALT — see Makefile and compile.sh.
// To generate a fresh value:  od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
#ifndef KEYRING_BUILD_SALT
#define KEYRING_BUILD_SALT \
    "162b6cceee498c4e1b9ac4418c4edd50" \
    "3eb5000e0db5c5a0a853a1f5d0f90181"
#endif
static const char g_szBuildSalt[] = KEYRING_BUILD_SALT;

// External secret file — created by srvguard on first run.
// Readable only by the service user (mode 0400).
static const char g_szKeyringSecretFile[] = "/var/lib/srvguard/keyring.secret";

// HexDecode converts a hex string to bytes.
// Returns number of bytes written, or -1 on error.
static int HexDecode (const char *pszHex, uint8_t *pbOut, size_t nMaxOut)
{
    size_t   nLen = strlen (pszHex);
    size_t   i;
    unsigned wHigh, wLow;

    if (nLen % 2 != 0 || nLen / 2 > nMaxOut)
        return -1;

    for (i = 0; i < nLen; i += 2)
    {
        if (sscanf (pszHex + i, "%1x%1x", &wHigh, &wLow) != 2)
            return -1;
        pbOut[i/2] = (uint8_t)((wHigh << 4) | wLow);
    }

    return (int)(nLen / 2);
}

// SrvGuardDeriveKeyLabel derives the keyring label from:
//   SHA256( build_salt || external_secret || boot_id )
// The first 16 bytes of the digest are hex-encoded to produce a
// 32-character label that is opaque and changes on every reboot.
// The build salt is baked into both binaries at compile time; the external
// secret file is created by srvguard on first run and is readable only by
// the service user — it never enters source control.
bool SrvGuardDeriveKeyLabel (char *pszLabel, size_t nLabelLen)
{
    uint8_t    abSalt[32]      = {0};
    uint8_t    abExternal[256] = {0};
    char       szBootID[64]    = {0};
    uint8_t    abDigest[32]    = {0};
    int        nIntLen         = 0;
    size_t     nExtLen         = 0;
    size_t     nBootLen        = 0;
    int        i               = 0;
    SHA256_CTX ctx;
    FILE      *pFile           = NULL;

    if (!pszLabel || nLabelLen < 33)
        return false;

    nIntLen = HexDecode (g_szBuildSalt, abSalt, sizeof (abSalt));
    if (nIntLen <= 0)
        return false;

    /* env var overrides the default path — useful for demos and testing */
    {
        const char *pszEnv = getenv ("SRVGUARD_KEYRING_SECRET_FILE");
        pFile = fopen (pszEnv && *pszEnv ? pszEnv : g_szKeyringSecretFile, "rb");
    }
    if (!pFile)
        return false;
    nExtLen = fread (abExternal, 1, sizeof (abExternal), pFile);
    fclose (pFile);
    pFile = NULL;
    if (nExtLen == 0)
        return false;

    pFile = fopen ("/proc/sys/kernel/random/boot_id", "r");
    if (!pFile)
        return false;
    nBootLen = fread (szBootID, 1, sizeof (szBootID) - 1, pFile);
    fclose (pFile);
    pFile = NULL;
    if (nBootLen == 0)
        return false;

    /* trim trailing whitespace */
    while (nBootLen > 0 && (szBootID[nBootLen-1] == '\n' || szBootID[nBootLen-1] == '\r'))
    {
        szBootID[nBootLen-1] = '\0';
        nBootLen--;
    }

    Sha256Init   (&ctx);
    Sha256Update (&ctx, abSalt,                  (size_t) nIntLen);
    Sha256Update (&ctx, abExternal,              nExtLen);
    Sha256Update (&ctx, (const uint8_t *)szBootID, nBootLen);
    Sha256Final  (&ctx, abDigest);

    for (i = 0; i < 16; i++)
        snprintf (pszLabel + i*2, 3, "%02x", abDigest[i]);
    pszLabel[32] = '\0';

    /* zero sensitive buffers */
    memset (abSalt,     0, sizeof (abSalt));
    memset (abExternal, 0, sizeof (abExternal));
    memset (&ctx,       0, sizeof (ctx));

    return true;
}

// keyctl command codes
#define KEYCTL_REVOKE   3
#define KEYCTL_READ     11
#define KEYCTL_SEARCH   10

// special keyring IDs
// KEY_SPEC_USER_KEYRING (-4) is shared across all processes of the same UID,
// regardless of session. This allows srvguard to run as a separate oneshot
// service and have the key visible to the Domino service that starts afterwards
// — without the credential file ever appearing in Domino's process namespace.
#define KEY_SPEC_USER_KEYRING     ((int)-4)

static long keyctl_call (int nCmd, unsigned long nArg2, unsigned long nArg3,
                          unsigned long nArg4, unsigned long nArg5)
{
    return syscall (SYS_keyctl, nCmd, nArg2, nArg3, nArg4, nArg5);
}

// KeyringReadInternal is the shared implementation for both read variants.
// bRevoke=true  — revokes the key after reading (one-time access, use for final consume)
// bRevoke=false — leaves the key in the keyring (use when a subsequent read is expected)
static bool KeyringReadInternal (const char *pszLabel,
                                  const char *pszField,
                                  char       *pszValue,
                                  size_t      nMaxLen,
                                  bool        bRevoke)
{
    if (!pszLabel || !pszField || !pszValue || nMaxLen == 0)
        return false;

    // search session keyring for our key
    long nSerial = keyctl_call (KEYCTL_SEARCH,
                                (unsigned long)(long) KEY_SPEC_USER_KEYRING,
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

    // revoke the key only when the caller wants final consumption (KEYCTL_REVOKE
    // marks the key as dead — no further reads are possible after this call)
    if (bRevoke)
        keyctl_call (KEYCTL_REVOKE, (unsigned long) nSerial, 0, 0, 0);

    // zero the JSON buffer before freeing
    memset (pszJson, 0, (size_t) nSize);
    free (pszJson);

    return bResult;
}

// SrvGuardKeyringRead reads a field and immediately revokes the key.
// Use this for the final consumer — after this call the key is gone.
bool SrvGuardKeyringRead (const char *pszLabel,
                          const char *pszField,
                          char       *pszValue,
                          size_t      nMaxLen)
{
    return KeyringReadInternal (pszLabel, pszField, pszValue, nMaxLen, true);
}

// SrvGuardKeyringPeek reads a field without revoking the key.
// Use this when a subsequent read of the same key is expected — for example
// MainEntryPoint peeks to set an initial password, then EM_GETPASSWORD reads
// and revokes via SrvGuardKeyringRead on the first Domino unlock call.
bool SrvGuardKeyringPeek (const char *pszLabel,
                          const char *pszField,
                          char       *pszValue,
                          size_t      nMaxLen)
{
    return KeyringReadInternal (pszLabel, pszField, pszValue, nMaxLen, false);
}

#else // non-Linux stubs

bool SrvGuardDeriveKeyLabel (char * /*pszLabel*/, size_t /*nLabelLen*/)
{
    return false; // keyring label derivation only available on Linux
}

bool SrvGuardKeyringRead (const char * /*pszLabel*/,
                          const char * /*pszField*/,
                          char       * /*pszValue*/,
                          size_t       /*nMaxLen*/)
{
    return false; // kernel keyring only available on Linux
}

bool SrvGuardKeyringPeek (const char * /*pszLabel*/,
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
