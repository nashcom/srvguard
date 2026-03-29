/*
 * domsrvguard — Domino Extension Manager for srvguard kernel keyring
 *
 * Reads the server password directly from the srvguard kernel keyring.
 * No external process, no files, no pipes.
 *
 * The key is revoked by SrvGuardKeyringRead immediately after the read.
 * All password buffers are zeroed before return.
 *
 * notes.ini:
 *   EXTMGR_ADDINS=domsrvguard
 *
 * For early startup (transaction log recovery):
 *   EXTMGR_ADDINS_EARLY=domsrvguard
 *
 * Initial password setup (passwordless ID):
 *   DomSrvGuardSetup=1
 *   Set once before first start. Cleared automatically after the password is set.
 *
 * Password rollover:
 *   Detected automatically in EM_GETPASSWORD when new_password is present
 *   in the srvguard keyring. No notes.ini change required.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern "C" {

#include "global.h"
#include "nsferr.h"
#include "osmisc.h"
#include "misc.h"
#include "extmgr.h"
#include "names.h"
#include "osenv.h"
#include "kfm.h"
#include "miscerr.h"
#include "bsafeerr.h"

} /* extern "C" */

#include "srvguard.hpp"

#define KEYRING_FIELD  "password"
#define KEYRING_NEW    "new_password"
#define MAX_PASSWORD   512

/*---- GLOBAL VARIABLES ----*/

static HEMREGISTRATION g_hHandler          = NULLHANDLE;
static DWORD           g_dwDebug           = 0;

/* Derived at startup — opaque 32-char hex, changes every reboot */
static char  g_szKeyringLabel[33]   = {0};

static char  g_szProgramName[]      = "DomSrvGuard";
static char  g_szProcess[MAXPATH+1] = {0};
static char *g_pszDisplayProcess    = g_szProcess;

/* Environment variables */
static char g_EnvPwSetup[] = "DomSrvGuardSetup";
static char g_EnvDebug[]   = "DomSrvGuardDebug";

/* ── helpers ─────────────────────────────────────────────────────────────── */

static void Log (const char *pszMessage)
{
    if (NULL == pszMessage)
        return;

    printf ("%s[%s]: %s\n", g_szProgramName, g_pszDisplayProcess, pszMessage);
    fflush (stdout);
}

static void Debug (const char *pszMessage)
{
    if (NULL == pszMessage)
        return;

    if (0 == g_dwDebug)
        return;

    printf ("%s[%s]: %s\n", g_szProgramName, g_pszDisplayProcess, pszMessage);
    fflush (stdout);
}

/* ── EM_GETPASSWORD ──────────────────────────────────────────────────────── */

extern "C" STATUS LNCALLBACK DomSrvGuardExtHandler (EMRECORD far *pRecord)
{
    STATUS  error        = ERR_EM_CONTINUE;
    STATUS  errChange    = NOERROR;
    DWORD   dwMaxPwdLen  = 0;
    DWORD   dwSafeLen    = 0;
    DWORD  *pdwLength    = NULL;
    char   *pszPassword  = NULL;
    char   *pszFileName  = NULL;
    char   *pszOwnerName = NULL;
    VARARG_PTR pArgs;

    char   szPassword[MAX_PASSWORD]    = {0};
    char   szNewPassword[MAX_PASSWORD] = {0};

    if (NULL == pRecord)
    {
        Log ("No EM record");
        goto Done;
    }

    if (pRecord->EId != EM_GETPASSWORD)
    {
        Log ("Wrong EM record");
        goto Done;
    }

    if (NOERROR != pRecord->Status)
    {
        Log ("Invalid status");
        goto Done;
    }

    VARARG_COPY (pArgs, pRecord->Ap);
    dwMaxPwdLen  = va_arg (pArgs, DWORD);
    pdwLength    = va_arg (pArgs, DWORD *);
    pszPassword  = va_arg (pArgs, char *);
    pszFileName  = va_arg (pArgs, char *);
    pszOwnerName = va_arg (pArgs, char *); (void) pszOwnerName;
    (void) va_arg (pArgs, DWORD);   /* DataLen — not used */
    (void) va_arg (pArgs, BYTE *);  /* Data    — not used */

    if (0 == dwMaxPwdLen)
    {
        Log ("Password buffer is 0");
        goto Done;
    }

    if (NULL == pdwLength)
    {
        Log ("Password length pointer is NULL");
        goto Done;
    }

    if (NULL == pszPassword)
    {
        Log ("Password buffer is NULL");
        goto Done;
    }

    /* Rollover — new_password present means change is pending */
    if (SrvGuardKeyringRead (g_szKeyringLabel, KEYRING_NEW, szNewPassword, sizeof (szNewPassword)))
    {
        if (!SrvGuardKeyringRead (g_szKeyringLabel, KEYRING_FIELD, szPassword, sizeof (szPassword)))
        {
            Log ("Rollover: cannot read current password");
            goto Done;
        }

        if (pszFileName)
        {
            errChange = SECKFMChangePassword (pszFileName, szPassword, szNewPassword);
            if (errChange)
                printf ("%s[%s]: Rollover: SECKFMChangePassword failed: 0x%x\n", g_szProgramName, g_pszDisplayProcess, errChange);
            else
                Log ("Password rollover complete");
        }

        /* ID now requires the new password */
        memcpy (szPassword, szNewPassword, sizeof (szPassword));
        SrvGuardZero (szNewPassword, sizeof (szNewPassword));
    }
    else
    {
        /* Normal unlock — SrvGuardKeyringRead consumes and revokes the key */
        if (!SrvGuardKeyringRead (g_szKeyringLabel, KEYRING_FIELD, szPassword, sizeof (szPassword)))
        {
            Log ("Keyring read failed");
            goto Done;
        }
    }

    dwSafeLen = dwMaxPwdLen < sizeof (szPassword) ? dwMaxPwdLen : (DWORD) sizeof (szPassword) - 1;
    *pdwLength = (DWORD) strnlen (szPassword, dwSafeLen);
    memcpy (pszPassword, szPassword, *pdwLength);

    if (g_dwDebug)
        printf ("%s[%s]: Password returned: %u\n", g_szProgramName, g_pszDisplayProcess, *pdwLength);

    error = ERR_BSAFE_EXTERNAL_PASSWORD;

Done:
    SrvGuardZero (szPassword,    sizeof (szPassword));
    SrvGuardZero (szNewPassword, sizeof (szNewPassword));
    return error;
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

extern "C" STATUS LNPUBLIC MainEntryPoint (void)
{
    STATUS  error                    = NOERROR;
    STATUS  errSetup                 = NOERROR;
    char   *p                        = g_szProcess;
    ssize_t len                      = 0;
    char    szIDFile[MAXPATH+1]      = {0};
    char    szPassword[MAX_PASSWORD] = {0};

    g_dwDebug = OSGetEnvironmentLong (g_EnvDebug);

    /* derive keyring label — opaque, boot-scoped, not guessable without secrets */
    if (!SrvGuardDeriveKeyLabel (g_szKeyringLabel, sizeof (g_szKeyringLabel)))
    {
        printf ("%s: Cannot derive keyring label — check %s\n",
                g_szProgramName, "/var/lib/srvguard/keyring.secret");
        error = ERR_MISC_INVALID_ARGS;
        goto Done;
    }

    len = readlink ("/proc/self/exe", g_szProcess, sizeof (g_szProcess));
    if (0 == len)
    {
        printf ("%s: Cannot get process name\n", g_szProgramName);
        error = ERR_MISC_INVALID_ARGS;
        goto Done;
    }

    while (*p)
    {
        if ('/' == *p)
            g_pszDisplayProcess = p + 1;
        p++;
    }

    /* Initial setup — set a password on a previously-passwordless ID.
     * SrvGuardKeyringPeek reads without revoking so the key remains available
     * for the EM_GETPASSWORD callback that Domino fires immediately after to
     * unlock the server. SrvGuardKeyringRead in the callback revokes the key. */
    if (OSGetEnvironmentLong (g_EnvPwSetup))
    {
        if (!OSGetEnvironmentString ("KeyFilename", szIDFile, sizeof (szIDFile)))
        {
            Log ("Initial setup: KeyFilename not set in notes.ini");
        }
        else if (!SrvGuardKeyringPeek (g_szKeyringLabel, KEYRING_FIELD, szPassword, sizeof (szPassword)))
        {
            Log ("Initial setup: keyring read failed");
        }
        else
        {
            errSetup = SECKFMChangePassword (szIDFile, NULL, szPassword);
            if (errSetup)
                printf ("%s[%s]: Initial setup: SECKFMChangePassword failed: 0x%x\n", g_szProgramName, g_pszDisplayProcess, errSetup);
            else
            {
                Log ("Initial password set");
                OSSetEnvironmentInt (g_EnvPwSetup, 0);
            }
        }
        SrvGuardZero (szPassword, sizeof (szPassword));
    }

    error = EMRegister (EM_GETPASSWORD, EM_REG_BEFORE, DomSrvGuardExtHandler, 0, &g_hHandler);
    if (error)
    {
        printf ("%s[%s]: EMRegister failed: %d\n", g_szProgramName, g_pszDisplayProcess, error);
        fflush (stdout);
        goto Done;
    }

    Debug ("Initialized");

Done:
    return error;
}
