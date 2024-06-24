package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;

/**
 * This class is used to verify applicability of a timestamp token within the signature validation process
 *
 */
public class TimestampTokenVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(TimestampTokenVerifier.class);

    /**
     * The trusted certificate source is used to accept trusted timestamp certificate chains
     */
    private CertificateSource trustedCertificateSource;

    /**
     * This variable indicates whether timestamps created only with trusted certificate chains shall be accepted
     */
    private boolean acceptUntrustedCertificateChains;

    /**
     * Default constructor
     */
    protected TimestampTokenVerifier() {
        // empty
    }

    /**
     * Creates an empty instance of TimestampTokenVerifier.
     * All constraints should be configured manually.
     *
     * @return {@link TimestampTokenVerifier}
     */
    public static TimestampTokenVerifier createEmptyTimestampTokenVerifier() {
        return new TimestampTokenVerifier();
    }

    /**
     * Creates a default instance of TimestampTokenVerifier, with pre-configured constraints.
     *
     * @return {@link TimestampTokenVerifier}
     */
    public static TimestampTokenVerifier createDefaultTimestampTokenVerifier() {
        final TimestampTokenVerifier timestampTokenVerifier = new TimestampTokenVerifier();
        timestampTokenVerifier.setAcceptUntrustedCertificateChains(false);
        return timestampTokenVerifier;
    }

    /**
     * Gets trusted certificate source, when present
     *
     * @return {@link CertificateSource}
     */
    public CertificateSource getTrustedCertificateSource() {
        return trustedCertificateSource;
    }

    /**
     * Sets a trusted certificate source in order to accept trusted timestamp certificate chains.
     * Note : This method is used internally during a {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *        initialization, in order to provide the same trusted source as the one used within
     *        a {@code eu.europa.esig.dss.validation.CertificateVerifier}.
     *
     * @param trustedCertificateSource {@link CertificateSource}
     */
    protected void setTrustedCertificateSource(CertificateSource trustedCertificateSource) {
        this.trustedCertificateSource = trustedCertificateSource;
    }

    /**
     * Sets whether only timestamp created with trusted certificate chains shall be considered as valid
     * Default: TRUE (only timestamps created with trusted CAs are considered as valid, untrusted timestamps are ignored)
     *
     * @param acceptUntrustedCertificateChains whether only trusted timestamps are considered as valid
     */
    public void setAcceptUntrustedCertificateChains(boolean acceptUntrustedCertificateChains) {
        this.acceptUntrustedCertificateChains = acceptUntrustedCertificateChains;
    }

    /**
     * This method verifies whether the given {@code timestampToken} is valid and acceptable,
     * and its POE can be extracted to the validation process.
     * NOTE: The method does not accept certificate chain, thus validity of the timestamp's certificate chain is not verified.
     * To successfully, execute this method, the parameter {@code acceptOnlyTrustedCertificateChains} shall be set to FALSE.
     * For validation with a certificate chain, please use {@code #isAcceptable(timestampToken, certificateChain)} method.
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @return TRUE if the timestampToken is valid and acceptable, FALSE otherwise
     */
    public boolean isAcceptable(TimestampToken timestampToken) {
        return isAcceptable(timestampToken, Collections.emptyList());
    }

    /**
     * This method verifies whether the given {@code timestampToken} is valid and acceptable,
     * and its POE can be extracted to the validation process
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @param certificateChain a list of {@link CertificateToken}s representing the certificate chain of the timestamp
     * @return TRUE if the timestampToken is valid and acceptable, FALSE otherwise
     */
    public boolean isAcceptable(TimestampToken timestampToken, List<CertificateToken> certificateChain) {
        return isTrustedTimestampToken(timestampToken, certificateChain) && isCryptographicallyValid(timestampToken);
    }

    /**
     * This method verifies whether the {@code timestampToken} is trusted to continue the process.
     * The method expects the certificate chain of the timestamp to reach a {@code trustedCertificateSource} or
     * to have {@code acceptOnlyTrustedCertificateChains} constraint to accept untrusted certificate chains as well.
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @param certificateChain a list of {@link CertificateToken}s representing the certificate chain of the timestamp
     * @return TRUE of the timestamp token is trusted, FALSE otherwise
     */
    protected boolean isTrustedTimestampToken(TimestampToken timestampToken, List<CertificateToken> certificateChain) {
        if (!acceptUntrustedCertificateChains && !containsTrustAnchor(certificateChain)) {
            LOG.warn("POE extraction is skipped for untrusted timestamp : {}.", timestampToken.getDSSIdAsString());
            return false;
        }
        return true;
    }

    private boolean containsTrustAnchor(List<CertificateToken> certChain) {
        if (Utils.isCollectionNotEmpty(certChain)) {
            for (CertificateToken token : certChain) {
                if (isTrusted(token)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isTrusted(CertificateToken certificateToken) {
        return trustedCertificateSource != null && trustedCertificateSource.isTrusted(certificateToken);
    }

    /**
     * This method verifies whether the {@code timestampToken} is cryptographically valid
     * (signature and message imprint match)
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @return TRUE if the timestamp token is cryptographically valid, FALSE otherwise
     */
    protected boolean isCryptographicallyValid(TimestampToken timestampToken) {
        if (!timestampToken.isMessageImprintDataIntact()) {
            LOG.warn("POE extraction is skipped for timestamp : {}. The message-imprint is not intact!",
                    timestampToken.getDSSIdAsString());
            return false;
        }
        if (!timestampToken.isSignatureIntact()) {
            LOG.warn("POE extraction is skipped for timestamp : {}. The signature is not intact!",
                    timestampToken.getDSSIdAsString());
            return false;
        }
        return true;
    }

}
