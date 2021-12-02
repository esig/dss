package eu.europa.esig.dss.token;

import eu.europa.esig.dss.model.DSSException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;

/**
 * Class provides an API for MacOS Keychain access.
 *
 * For more details please refer to the used documentation:
 * https://github.com/openjdk/jdk17u/blob/master/src/java.base/macosx/classes/apple/security/KeychainStore.java
 *
 */
public class AppleSignatureToken extends AbstractKeyStoreTokenConnection {

    @Override
    protected KeyStore getKeyStore() throws DSSException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("KeychainStore");
            keyStore.load(null, null);
        } catch (IOException | GeneralSecurityException e) {
            throw new DSSException("Unable to load MacOS Keychain store", e);
        }
        return keyStore;
    }

    @Override
    protected PasswordProtection getKeyProtectionParameter() {
        return new PasswordProtection("nimp".toCharArray());
    }

    @Override
    public void close() {
    }

}
