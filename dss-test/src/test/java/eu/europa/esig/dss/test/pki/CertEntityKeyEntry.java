package eu.europa.esig.dss.test.pki;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.token.DSSPrivateKeyAccessEntry;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * Implementation of {@code DSSPrivateKeyEntry} for a PKI {@code eu.europa.esig.dss.pki.model.CertEntity}
 *
 */
public class CertEntityKeyEntry implements DSSPrivateKeyAccessEntry {

    /** PKI Cert Entity entry */
    private final CertEntity certEntity;

    /**
     * Default constructor
     *
     * @param certEntity {@link CertEntity}
     */
    public CertEntityKeyEntry(final CertEntity certEntity) {
        Objects.requireNonNull(certEntity, "CertEntity cannot be null!");
        this.certEntity = certEntity;
    }

    @Override
    public CertificateToken getCertificate() {
        return certEntity.getCertificateToken();
    }

    @Override
    public CertificateToken[] getCertificateChain() {
        return certEntity.getCertificateChain().toArray(new CertificateToken[0]);
    }

    @Override
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return certEntity.getEncryptionAlgorithm();
    }

    @Override
    public PrivateKey getPrivateKey() {
        return certEntity.getPrivateKey();
    }

}
