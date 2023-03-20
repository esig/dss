package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;

import java.util.Collection;

/**
 * Provides certificates to be extracted by a URL
 *
 */
public interface X509URLCertificateSource extends CertificateSource {

    /**
     * Gets a collection of {@code CertificateToken}s retrieved from the given URI
     *
     * @param uri {@link String} to get a certificate tokens from
     * @return a collection of {@link CertificateToken}s
     */
    Collection<CertificateToken> getCertificatesByUrl(String uri);

}
