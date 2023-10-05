package eu.europa.esig.dss.test.pki;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.util.Collections;
import java.util.List;

/**
 * Represents a connection to a {@code eu.europa.esig.dss.pki.model.CertEntity} for signing using its private key connection
 *
 */
public class CertEntitySignatureTokenConnection extends AbstractSignatureTokenConnection {

    /** The PKI CertEntity used on signing */
    private final CertEntity certEntity;

    /**
     * Default constructor
     *
     * @param certEntity {@link CertEntity}
     */
    public CertEntitySignatureTokenConnection(final CertEntity certEntity) {
        this.certEntity = certEntity;
    }

    @Override
    public void close() {
        // not required
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
        return Collections.singletonList(new CertEntityKeyEntry(certEntity));
    }

}
