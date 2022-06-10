package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;

/**
 * This class is used to build a {@code RevocationDataLoadingStrategy}.
 *
 */
public abstract class RevocationDataLoadingStrategyBuilder {

    /**
     * The CRL revocation source
     */
    protected RevocationSource<CRL> crlSource;

    /**
     * The OCSP revocation source
     */
    protected RevocationSource<OCSP> ocspSource;

    /**
     * Used to verify the validity of obtained revocation data
     */
    protected RevocationDataVerifier revocationDataVerifier;

    /**
     * Defines whether a first obtained revocation token shall be returned, if none of them passed the verification.
     */
    protected boolean fallbackEnabled = false;

    /**
     * Sets the CRLSource.
     *
     * NOTE: This method is called by {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *       during the signature validation process
     *
     * @param crlSource {@link RevocationSource}
     * @return this {@link RevocationDataLoadingStrategyBuilder}
     */
    RevocationDataLoadingStrategyBuilder setCrlSource(RevocationSource<CRL> crlSource) {
        this.crlSource = crlSource;
        return this;
    }

    /**
     * Sets the OCSPSource.
     *
     * NOTE: This method is called by {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *       during the signature validation process
     *
     * @param ocspSource {@link RevocationSource}
     * @return this {@link RevocationDataLoadingStrategyBuilder}
     */
    RevocationDataLoadingStrategyBuilder setOcspSource(RevocationSource<OCSP> ocspSource) {
        this.ocspSource = ocspSource;
        return this;
    }

    /**
     * Sets {@code RevocationDataVerifier}.
     *
     * NOTE: This method is called by {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *       during the signature validation process
     *
     * @param revocationDataVerifier {@link RevocationDataVerifier}
     * @return this {@link RevocationDataLoadingStrategyBuilder}
     */
    RevocationDataLoadingStrategyBuilder setRevocationDataVerifier(RevocationDataVerifier revocationDataVerifier) {
        this.revocationDataVerifier = revocationDataVerifier;
        return this;
    }

    /**
     * This method sets behaviour whether the first obtained token still shall be returned,
     * when none of them have passed the acceptance verification.
     *
     * DEFAULT : FALSE - no fallback enabled. If all tokens fail the verification, then nothing is returned.
     *
     * @param fallbackEnabled TRUE if the fallback shall be enabled, FALSE otherwise
     * @return this {@link RevocationDataLoadingStrategyBuilder}
     */
    RevocationDataLoadingStrategyBuilder setFallbackEnabled(boolean fallbackEnabled) {
        this.fallbackEnabled = fallbackEnabled;
        return this;
    }

    /**
     * This method builds a {@code RevocationDataLoadingStrategy}
     *
     * @return {@link RevocationDataLoadingStrategy}
     */
    public RevocationDataLoadingStrategy build() {
        RevocationDataLoadingStrategy strategy = instantiate();
        strategy.setCrlSource(crlSource);
        strategy.setOcspSource(ocspSource);
        strategy.setRevocationDataVerifier(revocationDataVerifier);
        strategy.setFallbackEnabled(fallbackEnabled);
        return strategy;
    }

    /**
     * This method is used to create a {@code RevocationDataLoadingStrategy} instance
     *
     * @return {@link RevocationDataLoadingStrategy}
     */
    protected abstract RevocationDataLoadingStrategy instantiate();

}
