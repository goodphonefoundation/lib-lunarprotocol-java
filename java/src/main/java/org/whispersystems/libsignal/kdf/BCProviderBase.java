package org.whispersystems.libsignal.kdf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/*
Initialization of ouncyCastle provider.
BC specs: https://www.bouncycastle.org/specifications.html
* */
public class BCProviderBase {

    BCProviderBase() {
        setupBouncyCastle();
    }

    private void setupBouncyCastle() {
        final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            // Initialize BC provider for first use.
            return;
        }
        if (provider.getClass().equals(BouncyCastleProvider.class)) {
            // BC has been loaded or there is BC with the same package name.
            return;
        }
    /* Android registers its own BC provider. As it might be outdated and might not include
     all needed ciphers, we substitute it with a known BC bundled in the app.
     Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
     of that it's possible to have another BC implementation loaded in VM. */

        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
}
