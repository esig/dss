/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Date;
import java.util.List;

/**
 * This class is used to verify whether a given certificate token is trusted at the control time
 *
 */
public class TrustAnchorVerifier {

    /**
     * The trusted certificate source provides a source to trust anchors
     */
    private CertificateSource trustedCertificateSource;

    /**
     * This variable indicates whether timestamp's untrusted certificate chains shall be accepted
     */
    private boolean acceptTimestampUntrustedCertificateChains;

    /**
     * This variable indicates whether revocation data's untrusted certificate chains shall be accepted
     */
    private boolean acceptRevocationUntrustedCertificateChains;

    /**
     * This variable indicates whether the sunset date should be used for trust anchor determinations
     */
    private boolean useSunsetDate;

    /**
     * Default constructor
     */
    protected TrustAnchorVerifier() {
        // empty
    }

    /**
     * Creates an empty instance of TrustAnchorVerifier.
     * All constraints should be configured manually.
     *
     * @return {@link TrustAnchorVerifier}
     */
    public static TrustAnchorVerifier createEmptyTrustAnchorVerifier() {
        return new TrustAnchorVerifier();
    }

    /**
     * Creates a default instance of TrustAnchorVerifier, with pre-configured constraints.
     *
     * @return {@link TrustAnchorVerifier}
     */
    public static TrustAnchorVerifier createDefaultTrustAnchorVerifier() {
        final TrustAnchorVerifier trustAnchorVerifier = new TrustAnchorVerifier();
        trustAnchorVerifier.setUseSunsetDate(true);
        return trustAnchorVerifier;
    }

    /**
     * Gets whether untrusted certificate chains of timestamps should be accepted
     *
     * @return  whether only trusted timestamps are considered as valid
     */
    public boolean isAcceptTimestampUntrustedCertificateChains() {
        return acceptTimestampUntrustedCertificateChains;
    }

    /**
     * Sets whether untrusted certificate chains of timestamps should be accepted
     * Default: TRUE (only timestamps created with trusted CAs are considered as valid, untrusted timestamps are ignored)
     *
     * @param acceptTimestampUntrustedCertificateChains whether only trusted timestamps are considered as valid
     */
    public void setAcceptTimestampUntrustedCertificateChains(boolean acceptTimestampUntrustedCertificateChains) {
        this.acceptTimestampUntrustedCertificateChains = acceptTimestampUntrustedCertificateChains;
    }

    /**
     * Gets whether untrusted certificate chains of revocation data should be accepted
     *
     * @return  whether only trusted revocation data are considered as valid
     */
    public boolean isAcceptRevocationUntrustedCertificateChains() {
        return acceptRevocationUntrustedCertificateChains;
    }

    /**
     * Sets whether untrusted certificate chains of revocation data should be accepted
     * Default: TRUE (only revocation data created with trusted CAs are considered as valid, untrusted revocation data is ignored)
     *
     * @param acceptRevocationUntrustedCertificateChains whether only trusted timestamps are considered as valid
     */
    public void setAcceptRevocationUntrustedCertificateChains(boolean acceptRevocationUntrustedCertificateChains) {
        this.acceptRevocationUntrustedCertificateChains = acceptRevocationUntrustedCertificateChains;
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
     * Sets a trusted certificate source in order to provide information about the available trust anchors.
     * Note : This method is used internally during a {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *        initialization, in order to provide the same trusted source as the one used within
     *        a {@code eu.europa.esig.dss.validation.CertificateVerifier}.
     *
     * @param trustedCertificateSource {@link CertificateSource}
     */
    public void setTrustedCertificateSource(CertificateSource trustedCertificateSource) {
        this.trustedCertificateSource = trustedCertificateSource;
    }

    /**
     * Defines whether sunset date shall be considered during trust anchor validation
     *
     * @return whether a trust anchor's sunset date shall be taken into account
     */
    public boolean isUseSunsetDate() {
        return useSunsetDate;
    }

    /**
     * Sets whether a trust anchor's sunset date shall be taken into account when checking a trust anchor
     * Default : TRUE (sunset date is used for a trust anchor determination, when applicable)
     *
     * @param useSunsetDate whether a trust anchor's sunset date shall be taken into account
     */
    public void setUseSunsetDate(boolean useSunsetDate) {
        this.useSunsetDate = useSunsetDate;
    }

    /**
     * This method verifies whether the {@code certificateToken} is trusted at {@code controlTime}
     *
     * @param certificateToken {@link CertificateToken} to check
     * @param controlTime {@link Date} the validation time
     * @return TRUE if the certificate is trusted at the given time, FALSE otherwise
     */
    public boolean isTrustedAtTime(CertificateToken certificateToken, Date controlTime) {
        return isTrustedAtTime(certificateToken, controlTime, null);
    }

    /**
     * This method verifies whether the {@code certificateToken} is trusted at {@code controlTime}
     *
     * @param certificateToken {@link CertificateToken} to check
     * @param controlTime {@link Date} the validation time
     * @param context {@link Context}
     * @return TRUE if the certificate is trusted at the given time, FALSE otherwise
     */
    public boolean isTrustedAtTime(CertificateToken certificateToken, Date controlTime, Context context) {
        if (isAcceptUntrustedCertificateChains(context)) {
            return true;
        } else if (trustedCertificateSource == null) {
            return false;
        } else if (useSunsetDate && controlTime != null) {
            return trustedCertificateSource.isTrustedAtTime(certificateToken, controlTime);
        } else {
            return trustedCertificateSource.isTrusted(certificateToken);
        }
    }

    /**
     * Verifies whether the certificate chain contains a trust anchor
     *
     * @param certChain a list of {@link CertificateToken}s representing a certificate chain to be verified
     * @param controlTime {@link Date} validation time
     * @return TRUE if the certificate chain is trusted, FALSE otherwise
     */
    public boolean isTrustedCertificateChain(List<CertificateToken> certChain, Date controlTime) {
        return isTrustedCertificateChain(certChain, controlTime, null);
    }

    /**
     * Verifies whether the certificate chain contains a trust anchor
     *
     * @param certChain a list of {@link CertificateToken}s representing a certificate chain to be verified
     * @param controlTime {@link Date} validation time
     * @param context {@link Context}
     * @return TRUE if the certificate chain is trusted, FALSE otherwise
     */
    public boolean isTrustedCertificateChain(List<CertificateToken> certChain, Date controlTime, Context context) {
        if (isAcceptUntrustedCertificateChains(context)) {
            return true;
        }
        if (Utils.isCollectionNotEmpty(certChain)) {
            for (CertificateToken token : certChain) {
                if (isTrustedAtTime(token, controlTime, context)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isAcceptUntrustedCertificateChains(Context context) {
        if (Context.TIMESTAMP == context) {
            return acceptTimestampUntrustedCertificateChains;
        } else if (Context.REVOCATION == context) {
            return acceptRevocationUntrustedCertificateChains;
        }
        return false; // continue in other cases
    }

}
