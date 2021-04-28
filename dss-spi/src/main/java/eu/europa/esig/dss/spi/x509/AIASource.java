package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.Set;

/**
 * Interface that allows loading of issuing certificates
 * by defined AIA URI within a {@code eu.europa.esig.dss.model.x509.CertificateToken}
 *
 */
public interface AIASource {

    /**
     * Loads a set of {@code CertificateToken}s accessed by AIA URIs from the provided {@code certificateToken}
     *
     * @param certificateToken {@link CertificateToken} to get issuer candidates for
     * @return a set of issuer candidates accessed by AIA URIs
     */
    Set<CertificateToken> getCertificatesByAIA(final CertificateToken certificateToken);

}
