/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * This class is used to verify applicability of a timestamp token within the signature validation process
 *
 */
public class TimestampTokenVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(TimestampTokenVerifier.class);

    /**
     * Verifies whether a given certificate token is a trust anchor at the control time
     */
    private TrustAnchorVerifier trustAnchorVerifier;

    /**
     * Verifies validity of the certificate's revocation data for timestamps's certificate chain
     */
    private RevocationDataVerifier revocationDataVerifier;

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
        // no configuration available
        return timestampTokenVerifier;
    }

    /**
     * Gets a trust anchor verifier.
     * This method is used internally within {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     * to identify whether the configuration is already present and a {@code trustAnchorVerifier} should be set.
     *
     * @return {@link TrustAnchorVerifier}
     */
    public TrustAnchorVerifier getTrustAnchorVerifier() {
        return trustAnchorVerifier;
    }

    /**
     * Sets whether a certificate token can be considered as a trust anchor at the given control time
     * Note : This method is used internally during a {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *        initialization, when not defined explicitly, in order to provide the same configuration as the one used within
     *        a {@code eu.europa.esig.dss.validation.CertificateVerifier}.
     *
     * @param trustAnchorVerifier {@link TrustAnchorVerifier}
     */
    public void setTrustAnchorVerifier(TrustAnchorVerifier trustAnchorVerifier) {
        this.trustAnchorVerifier = trustAnchorVerifier;
    }

    /**
     * Gets a revocation data verifier.
     * This method is used internally within {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     * to identify whether the configuration is already present and a {@code trustAnchorVerifier} should be set.
     *
     * @return {@link TrustAnchorVerifier}
     */
    public RevocationDataVerifier getRevocationDataVerifier() {
        if (revocationDataVerifier != null && revocationDataVerifier.getTrustAnchorVerifier() == null) {
            revocationDataVerifier.setTrustAnchorVerifier(getTrustAnchorVerifier());
        }
        return revocationDataVerifier;
    }

    /**
     * Sets a revocation data verifier for validation of timestamp's certificate chain revocation data validity
     * Note : This method is used internally during a {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *        initialization, when not defined explicitly, in order to provide the same configuration as the one used within
     *        a {@code eu.europa.esig.dss.validation.CertificateVerifier}.
     *
     * @param revocationDataVerifier {@link RevocationDataVerifier}
     */
    public void setRevocationDataVerifier(RevocationDataVerifier revocationDataVerifier) {
        this.revocationDataVerifier = revocationDataVerifier;
    }

    /**
     * This method verifies whether the given {@code timestampToken} is valid and acceptable at the current time,
     * and its POE can be extracted to the validation process.
     * NOTE: The method does not accept certificate chain, thus validity of the timestamp's certificate chain is not verified.
     * To successfully, execute this method, the parameter {@code acceptOnlyTrustedCertificateChains} shall be set to FALSE.
     * For validation with a certificate chain, please use {@code #isAcceptable(timestampToken, certificateChain)} method.
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @return TRUE if the timestampToken is valid and acceptable, FALSE otherwise
     */
    public boolean isAcceptable(TimestampToken timestampToken) {
        return isAcceptable(timestampToken, new Date());
    }

    /**
     * This method verifies whether the given {@code timestampToken} is valid and acceptable at the given control time,
     * and its POE can be extracted to the validation process.
     * NOTE: The method does not accept certificate chain, thus validity of the timestamp's certificate chain is not verified.
     * To successfully, execute this method, the parameter {@code acceptOnlyTrustedCertificateChains} shall be set to FALSE.
     * For validation with a certificate chain, please use {@code #isAcceptable(timestampToken, certificateChain)} method.
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @param controlTime {@link Date} the validation time
     * @return TRUE if the timestampToken is valid and acceptable, FALSE otherwise
     */
    public boolean isAcceptable(TimestampToken timestampToken, Date controlTime) {
        return isAcceptable(timestampToken, Collections.emptyList(), controlTime);
    }

    /**
     * This method verifies whether the given {@code timestampToken} is valid and acceptable at the current time,
     * and its POE can be extracted to the validation process
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @param certificateChain a list of {@link CertificateToken}s representing the certificate chain of the timestamp
     * @return TRUE if the timestampToken is valid and acceptable, FALSE otherwise
     */
    public boolean isAcceptable(TimestampToken timestampToken, List<CertificateToken> certificateChain) {
        return isAcceptable(timestampToken, certificateChain, new Date());
    }

    /**
     * This method verifies whether the given {@code timestampToken} is valid and acceptable at the given control time,
     * and its POE can be extracted to the validation process
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @param certificateChain a list of {@link CertificateToken}s representing the certificate chain of the timestamp
     * @param controlTime {@link Date} the validation time
     * @return TRUE if the timestampToken is valid and acceptable, FALSE otherwise
     */
    public boolean isAcceptable(TimestampToken timestampToken, List<CertificateToken> certificateChain, Date controlTime) {
        return isTrustedTimestampToken(timestampToken, certificateChain, controlTime) && isCryptographicallyValid(timestampToken)
                && isCertificateChainValid(certificateChain, controlTime);
    }

    /**
     * This method verifies whether the {@code timestampToken} is trusted to continue the process at the control time.
     * The method expects the certificate chain of the timestamp to reach a {@code trustedCertificateSource} or
     * to have {@code acceptOnlyTrustedCertificateChains} constraint to accept untrusted certificate chains as well.
     *
     * @param timestampToken {@link TimestampToken} to be validated
     * @param certificateChain a list of {@link CertificateToken}s representing the certificate chain of the timestamp
     * @param controlTime {@link Date} to verify the trust anchor's validity period
     * @return TRUE of the timestamp token is trusted, FALSE otherwise
     */
    protected boolean isTrustedTimestampToken(TimestampToken timestampToken, List<CertificateToken> certificateChain, Date controlTime) {
        if (containsTrustAnchor(certificateChain, controlTime)) {
            return true;
        }
        LOG.warn("POE extraction is skipped for untrusted timestamp : {}.", timestampToken.getDSSIdAsString());
        return false;
    }

    /**
     * This method verifies whether the certificate chain is trusted at the given time
     *
     * @param certChain a list of {@link CertificateToken}s representing a certificate chain to validate
     * @param controlTime {@link Date} validation time
     * @return TRUE if the certificate chain is trusted, FALSE otherwise
     */
    protected boolean containsTrustAnchor(List<CertificateToken> certChain, Date controlTime) {
        final TrustAnchorVerifier currentTrustAnchorVerifier = getTrustAnchorVerifier();
        if (currentTrustAnchorVerifier == null) {
            LOG.debug("TrustAnchorVerifier is not defined! None of the certificates will be considered as a trust anchor.");
            return false;
        }
        return currentTrustAnchorVerifier.isTrustedCertificateChain(certChain, controlTime, Context.TIMESTAMP);
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

    /**
     * This method verifies certificate chain and presence of a valid revocation data for certificates
     *
     * @param certificateChain a list of {@link CertificateToken}s
     * @param controlTime {@link Date} validation time
     * @return TRUE if the certificate chain is valid, FALSE otherwise
     */
    protected boolean isCertificateChainValid(List<CertificateToken> certificateChain, Date controlTime) {
        RevocationDataVerifier currentRevocationDataVerifier = getRevocationDataVerifier();
        if (revocationDataVerifier == null) {
            LOG.warn("No RevocationDataVerifier is provided! Revocation check is skipped.");
            return true;
        }
        return currentRevocationDataVerifier.isCertificateChainValid(certificateChain, controlTime, Context.TIMESTAMP);
    }

}
