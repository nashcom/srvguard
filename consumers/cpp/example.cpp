// example.cpp — demonstrates both consumer backends

#include "srvguard.hpp"
#include <stdio.h>
#include <string.h>

int main (void)
{
    // --- keyring backend ---
    // srvguard must have stored the secret in the session keyring
    // before this process starts (e.g. launched by srvguard itself)

    char szPassword[512] = {};

    if (SrvGuardKeyringRead ("srvguard", "key_password", szPassword, sizeof (szPassword)))
    {
        printf ("keyring: got password (%zu chars)\n", strlen (szPassword));
        // use szPassword here ...
        SrvGuardZero (szPassword, sizeof (szPassword));
    }
    else
    {
        printf ("keyring: key not found — trying files backend\n");

        // --- files backend ---
        char szChain[65536]  = {};
        char szKey[65536]    = {};

        bool bChain = SrvGuardFileRead ("/run/srvguard/certs", "server.crt",
                                         szChain, sizeof (szChain));
        bool bKey   = SrvGuardFileRead ("/run/srvguard/certs", "server.key",
                                         szKey, sizeof (szKey));
        bool bPass  = SrvGuardFileRead ("/run/srvguard/certs", "ssl.password",
                                         szPassword, sizeof (szPassword));

        printf ("files: chain=%s key=%s password=%s\n",
                bChain ? "ok" : "missing",
                bKey   ? "ok" : "missing",
                bPass  ? "ok" : "missing");

        SrvGuardZero (szChain,    sizeof (szChain));
        SrvGuardZero (szKey,      sizeof (szKey));
        SrvGuardZero (szPassword, sizeof (szPassword));
    }

    return 0;
}
