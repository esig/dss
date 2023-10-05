package eu.europa.esig.dss.token;

import java.security.PrivateKey;

/**
 * Provides an interface to a token connection with an exposed (accessible) private key entry.
 * NOTE: That does not mean that the cryptographic private key can be extracted.
 * The interface is meant to only provide direct access to the private key.
 * It is up to the underlying implementation to determine a way the private key can be accessed.
 */
public interface DSSPrivateKeyAccessEntry extends DSSPrivateKeyEntry {

    /**
     * Gets the private key
     *
     * @return the private key
     */
    PrivateKey getPrivateKey();

}
