package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.List;

/**
 * The interface provides an abstraction of a {@code eu.europa.esig.dss.spi.x509.CertificateSource}
 * containing trust anchors
 *
 */
public interface TrustedCertificateSource extends CertificateSource {

    /**
     * Returns a list of alternative OCSP access point Urls for certificates issued by the current trust anchor
     *
     * @param trustAnchor {@link CertificateToken}
     * @return a list of {@link String}s
     */
    List<String> getAlternativeOCSPUrls(CertificateToken trustAnchor);

    /**
     * Returns a list of alternative CRL access point Urls for certificates issued by the current trust anchor
     *
     * @param trustAnchor {@link CertificateToken}
     * @return a list of {@link String}s
     */
    List<String> getAlternativeCRLUrls(CertificateToken trustAnchor);

}
