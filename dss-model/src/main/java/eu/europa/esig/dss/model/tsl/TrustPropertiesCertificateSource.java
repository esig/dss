package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.List;
import java.util.Map;

/**
 * This interface provides an abstraction for a certificate source containing information about
 * a validation status of Trusted Lists and corresponding trust properties
 *
 */
public interface TrustPropertiesCertificateSource {

    /**
     * Gets TL Validation job summary
     *
     * @return {@link TLValidationJobSummary}
     */
    TLValidationJobSummary getSummary();

    /**
     * Sets TL Validation job summary
     *
     * @param summary {@link TLValidationJobSummary}
     */
    void setSummary(TLValidationJobSummary summary);

    /**
     * Returns TrustProperties for the given certificate, when applicable
     *
     * @param token {@link CertificateToken}
     * @return a list of {@link TrustProperties}
     */
    List<TrustProperties> getTrustServices(CertificateToken token);

    /**
     * The method allows to fill the CertificateSource
     *
     * @param trustPropertiesByCerts map between {@link CertificateToken}s and a list of {@link TrustProperties}
     */
    void setTrustPropertiesByCertificates(final Map<CertificateToken, List<TrustProperties>> trustPropertiesByCerts);

}
