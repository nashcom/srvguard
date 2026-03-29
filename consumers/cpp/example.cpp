// example.cpp — demonstrates both consumer backends

#include "srvguard.hpp"
#include <stdio.h>
#include <string.h>

int main (void)
{
    char szLabel[33]    = {0};
    char szPassword[512] = {0};

    // --- keyring backend ---
    // srvguard must have stored the secret in the keyring before this process
    // starts. The label is derived from the internal secret, the external
    // secret file (SRVGUARD_KEYRING_SECRET_FILE or /var/lib/srvguard/keyring.secret),
    // and the current boot ID — never hardcoded.

    if (!SrvGuardDeriveKeyLabel (szLabel, sizeof (szLabel)))
    {
        printf ("keyring: cannot derive label — check SRVGUARD_KEYRING_SECRET_FILE\n");
    }
    else if (SrvGuardKeyringRead (szLabel, "key_password", szPassword, sizeof (szPassword)))
    {
        printf ("keyring: label  = %s\n", szLabel);
        printf ("keyring: got password (%zu chars)\n", strlen (szPassword));
        // use szPassword here ...
        SrvGuardZero (szPassword, sizeof (szPassword));
        return 0;
    }
    else
    {
        printf ("keyring: label  = %s\n", szLabel);
        printf ("keyring: key not found — trying files backend\n");
    }

    // --- files backend ---
    char szChain[65536] = {0};
    char szKey[65536]   = {0};

    bool bChain = SrvGuardFileRead ("/run/srvguard/certs", "server.crt",  szChain,    sizeof (szChain));
    bool bKey   = SrvGuardFileRead ("/run/srvguard/certs", "server.key",  szKey,      sizeof (szKey));
    bool bPass  = SrvGuardFileRead ("/run/srvguard/certs", "ssl.password", szPassword, sizeof (szPassword));

    printf ("files: chain=%s key=%s password=%s\n",
            bChain ? "ok" : "missing",
            bKey   ? "ok" : "missing",
            bPass  ? "ok" : "missing");

    SrvGuardZero (szChain,    sizeof (szChain));
    SrvGuardZero (szKey,      sizeof (szKey));
    SrvGuardZero (szPassword, sizeof (szPassword));

    return 0;
}
