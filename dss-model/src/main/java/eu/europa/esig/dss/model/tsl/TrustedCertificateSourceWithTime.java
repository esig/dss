package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * This trusted certificate source defines a collection of trusted certificates with a given trusted validity range,
 * during which a certificate is considered as a trust anchor
 *
 */
public interface TrustedCertificateSourceWithTime {

    /**
     * Returns trust time period for the given certificate, when the certificate is considered as a trust anchor.
     * For an unbounded period of trust time, returns a {@code CertificateTrustTime} with empty values.
     * When the certificate is not trusted at any time, returns not trusted {@code CertificateTrustTime} entry.
     *
     * @param token {@link CertificateToken}
     * @return {@link CertificateTrustTime}
     */
    CertificateTrustTime getTrustTime(CertificateToken token);

}
