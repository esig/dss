package eu.europa.esig.dss.pki.x509.tsp;

import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;

/**
 * A class that represents a PKI Time Stamp Protocol (TSP) source extending the KeyEntityTSPSource.
 * It provides functionality to generate time-stamp responses for given digest algorithms and digests.
 */
public class PKITSPSource extends KeyEntityTSPSource {

    private static final long serialVersionUID = -7408921046892174782L;

    /**
     * Constructs a new PkiTSPSource instance with the specified certificate entity.
     *
     * @param certEntity The certificate entity associated with the TSP source.
     */
    public PKITSPSource(CertEntity certEntity) {
        super(certEntity.getPrivateKey(), certEntity.getCertificateToken(), certEntity.getCertificateChain());
    }

}
