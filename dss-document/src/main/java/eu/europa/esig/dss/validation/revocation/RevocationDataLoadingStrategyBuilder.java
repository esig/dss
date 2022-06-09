package eu.europa.esig.dss.validation.revocation;

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
     * Sets the CRLSource
     *
     * @param crlSource {@link RevocationSource}
     * @return this {@link RevocationDataLoadingStrategyBuilder}
     */
    public RevocationDataLoadingStrategyBuilder setCrlSource(RevocationSource<CRL> crlSource) {
        this.crlSource = crlSource;
        return this;
    }

    /**
     * Sets the OCSPSource
     *
     * @param ocspSource {@link RevocationSource}
     * @return this {@link RevocationDataLoadingStrategyBuilder}
     */
    public RevocationDataLoadingStrategyBuilder setOcspSource(RevocationSource<OCSP> ocspSource) {
        this.ocspSource = ocspSource;
        return this;
    }

    /**
     * Sets {@code RevocationDataVerifier}
     *
     * @param revocationDataVerifier {@link RevocationDataVerifier}
     * @return this {@link RevocationDataLoadingStrategyBuilder}
     */
    public RevocationDataLoadingStrategyBuilder setRevocationDataVerifier(RevocationDataVerifier revocationDataVerifier) {
        this.revocationDataVerifier = revocationDataVerifier;
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
        return strategy;
    }

    /**
     * This method is used to create a {@code RevocationDataLoadingStrategy} instance
     *
     * @return {@link RevocationDataLoadingStrategy}
     */
    protected abstract RevocationDataLoadingStrategy instantiate();

}
