package eu.europa.esig.dss.pki.model;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;
import java.security.PrivateKey;
import java.util.List;

/**
 * An interface representing a certificate entity with essential properties.
 * <p>
 * This interface defines methods to access key information, certificate chain, the certificate token,
 * and the encryption algorithm associated with the certificate entity.
 *
 * @see CertificateToken
 * @see EncryptionAlgorithm
 */
public interface CertEntity extends Serializable {

    /**
     * Gets the private key associated with this certificate entity.
     *
     * @return private key as a {@link PrivateKey} object
     */
    PrivateKey getPrivateKeyObject();

    /**
     * Gets the certificate chain associated with this certificate entity.
     *
     * @return a list of {@link CertificateToken} objects representing the certificate chain.
     */
    List<CertificateToken> getCertificateChain();

    /**
     * Gets the certificate token associated with this certificate entity.
     *
     * @return the certificate token as a {@link CertificateToken} object.
     */
    CertificateToken getCertificateToken();

    /**
     * Gets the encryption algorithm associated with this certificate entity.
     *
     * @return the encryption algorithm as an {@link EncryptionAlgorithm} object.
     */
    EncryptionAlgorithm getEncryptionAlgorithm();

}
