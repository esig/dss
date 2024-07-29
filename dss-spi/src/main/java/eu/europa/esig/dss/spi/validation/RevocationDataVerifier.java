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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.CertificateExtension;
import eu.europa.esig.dss.model.x509.extension.CertificateExtensions;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicies;
import eu.europa.esig.dss.model.x509.extension.CertificatePolicy;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSPKUtils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class is used to verify acceptance of a revocation data for the following validation process,
 * whether the revocation data has been extracted from a document or obtained from an online source.
 * The class verifies the consistency of the given revocation information and
 * applicability of the used cryptographic constraints used to create this token.
 *
 * NOTE: It is not recommended to use a single instance of {@code RevocationDataVerifier}
 *       within different {@code CertificateVerifier}s, as it may lead to concurrency issues during the execution
 *       in multi-threaded environments.
 *       Please use a new {@code RevocationDataVerifier} per each {@code CertificateVerifier}.
 *
 */
public class RevocationDataVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationDataVerifier.class);

    /** Default collection of acceptable digest algorithms */
    private static final Collection<DigestAlgorithm> DEFAULT_DIGEST_ALGORITHMS;

    /** Default map of acceptable encryption algorithms and their corresponding key length */
    private static final Map<EncryptionAlgorithm, Integer> DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP;

    /** Default collection of certificate extension OIDs for revocation data check skip */
    private static final Collection<String> DEFAULT_REVOCATION_SKIP_CERTIFICATE_EXTENSIONS;

    /** Default maximum revocation freshness */
    private static final Long DEFAULT_MAXIMUM_REVOCATION_FRESHNESS = 0L;

    static {
        DEFAULT_DIGEST_ALGORITHMS = Arrays.asList(
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512);

        DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP = new HashMap<>();
        DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP.put(EncryptionAlgorithm.DSA, 2048);
        DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP.put(EncryptionAlgorithm.RSA, 1900);
        DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP.put(EncryptionAlgorithm.RSASSA_PSS, 1900);
        DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP.put(EncryptionAlgorithm.ECDSA, 256);
        DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP.put(EncryptionAlgorithm.PLAIN_ECDSA, 256);

        DEFAULT_REVOCATION_SKIP_CERTIFICATE_EXTENSIONS = Arrays.asList(
                OID.id_etsi_ext_valassured_ST_certs.getId(), OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId(),
                Extension.noRevAvail.getId()
        );
    }

    /**
     * The trusted certificate source is used to accept trusted revocation data issuer certificates
     */
    private CertificateSource trustedCertificateSource;

    /**
     * A collection of Digest Algorithms to accept from CRL/OCSP responders.
     * Note : revocation tokens created with digest algorithms other than listed in this collection will be skipped.
     * Default : collection of algorithms is synchronized with ETSI 119 312 V1.4.2
     */
    private Collection<DigestAlgorithm> acceptableDigestAlgorithms;

    /**
     * Map of acceptable Encryption Algorithms with a corresponding minimal acceptable key length for each algorithm.
     * Note : revocation tokens created with encryption algorithms other than listed in this map or
     *        with a key size smaller than defined in the map will be skipped.
     * Default : collection of algorithms is synchronized with ETSI 119 312 V1.4.2
     */
    private Map<EncryptionAlgorithm, Integer> acceptableEncryptionAlgorithmKeyLength;

    /**
     * Collection of certificate extension identifiers indicating the revocation check is not required for those certificates
     * Default : valassured-ST-certs (OID: "0.4.0.194121.2.1") and ocsp_noCheck (OID: "1.3.6.1.5.5.7.48.1.5")
     */
    private Collection<String> revocationSkipCertificateExtensions;

    /**
     * Collection of certificate policy identifiers indicating the revocation check is not required for those certificates
     * Default : empty list
     */
    private Collection<String> revocationSkipCertificatePolicies;

    /**
     * Defines maximum allowed revocation freshness for signature's certificate chain
     * Default : 0 (revocation must be issued after the best-signature-time)
     */
    private Long signatureMaximumRevocationFreshness;

    /**
     * Defines maximum allowed revocation freshness for timestamp's certificate chain
     * Default : 0 (revocation must be issued after the lowest time-stamp's POE)
     * Note : revocation data shall be issued after the last usage time of the certificate
     */
    private Long timestampMaximumRevocationFreshness;

    /**
     * Defines maximum allowed revocation freshness for revocation's certificate chain
     * Default : 0 (revocation must be issued after the lowest revocation's POE)
     */
    private Long revocationMaximumRevocationFreshness;

    /**
     * When set to TRUE and no revocation maximum freshness is defined for the given context,
     * enforces revocation freshness check using a difference between revocation's
     * nextUpdate and thisUpdate as the maximum acceptable revocation freshness.
     */
    private boolean checkRevocationFreshnessNextUpdate;

    /**
     * Default constructor
     */
    protected RevocationDataVerifier() {
        // empty
    }

    /**
     * Creates an empty instance of RevocationDataVerifier.
     * All constraints should be configured manually.
     *
     * @return {@link RevocationDataVerifier}
     */
    public static RevocationDataVerifier createEmptyRevocationDataVerifier() {
        return new RevocationDataVerifier();
    }

    /**
     * This method is used to instantiate a new {@code RevocationDataVerifier}, using the default validation constraints
     * (synchronized with default validation policy).
     *
     * @return {@link RevocationDataVerifier}
     */
    public static RevocationDataVerifier createDefaultRevocationDataVerifier() {
        try {
            final RevocationDataVerifier revocationDataVerifier = new RevocationDataVerifier();
            revocationDataVerifier.setAcceptableDigestAlgorithms(DEFAULT_DIGEST_ALGORITHMS);
            revocationDataVerifier.setAcceptableEncryptionAlgorithmKeyLength(DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP);
            revocationDataVerifier.setRevocationSkipCertificateExtensions(DEFAULT_REVOCATION_SKIP_CERTIFICATE_EXTENSIONS);
            // #revocationSkipCertificatePolicies are empty
            revocationDataVerifier.setSignatureMaximumRevocationFreshness(DEFAULT_MAXIMUM_REVOCATION_FRESHNESS);
            revocationDataVerifier.setTimestampMaximumRevocationFreshness(DEFAULT_MAXIMUM_REVOCATION_FRESHNESS);
            revocationDataVerifier.setRevocationMaximumRevocationFreshness(DEFAULT_MAXIMUM_REVOCATION_FRESHNESS);
            // #checkRevocationFreshnessNextUpdate is false
            return revocationDataVerifier;
        } catch (Exception e) {
            throw new DSSException(String.format(
                    "Unable to instantiate default RevocationDataVerifier. Reason : %s", e.getMessage()), e);
        }
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
     * Sets a trusted certificate source in order to accept trusted revocation data issuer certificates.
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
     * Sets a collection of Digest Algorithms for acceptance.
     * If a revocation token is signed with an algorithm other than listed in the collection, the token will be skipped.
     * Default : collection of algorithms is synchronized with ETSI 119 312 V1.4.2
     *
     * @param acceptableDigestAlgorithms a collection if {@link DigestAlgorithm}s
     */
    public void setAcceptableDigestAlgorithms(Collection<DigestAlgorithm> acceptableDigestAlgorithms) {
        Objects.requireNonNull(acceptableDigestAlgorithms, "Collection of DigestAlgorithms for acceptance cannot be null!");
        this.acceptableDigestAlgorithms = acceptableDigestAlgorithms;
    }

    /**
     * Sets a map of acceptable Encryption Algorithms and their corresponding minimal key length values.
     * If a revocation token is signed with an algorithm other than listed in the collection or with a smaller key size,
     * than the token will be skipped.
     * Default : collection of algorithms is synchronized with ETSI 119 312 V1.4.2
     *
     * @param acceptableEncryptionAlgorithmKeyLength a map of {@link EncryptionAlgorithm}s and
     *                                               their corresponding minimal supported key lengths
     */
    public void setAcceptableEncryptionAlgorithmKeyLength(Map<EncryptionAlgorithm, Integer> acceptableEncryptionAlgorithmKeyLength) {
        Objects.requireNonNull(acceptableEncryptionAlgorithmKeyLength, "Map of Encryption Algorithms for acceptance cannot be null!");
        this.acceptableEncryptionAlgorithmKeyLength = acceptableEncryptionAlgorithmKeyLength;
    }

    /**
     * Sets a collection of certificate extension OIDs indicating the revocation check shall be skipped
     * for the given certificate
     * Default : valassured-ST-certs (OID: "0.4.0.194121.2.1") and ocsp_noCheck (OID: "1.3.6.1.5.5.7.48.1.5")
     *           (extracted from validation policy)
     *
     * @param revocationSkipCertificateExtensions a collection of {@link String}s certificate extension OIDs
     */
    public void setRevocationSkipCertificateExtensions(Collection<String> revocationSkipCertificateExtensions) {
        this.revocationSkipCertificateExtensions = revocationSkipCertificateExtensions;
    }

    /**
     * Sets a collection of certificate policy OIDs indicating the revocation check shall be skipped for the given certificate
     * Default : empty list (extracted from validation policy)
     *
     * @param revocationSkipCertificatePolicies a collection of {@link String}s certificate policy OIDs
     */
    public void setRevocationSkipCertificatePolicies(Collection<String> revocationSkipCertificatePolicies) {
        this.revocationSkipCertificatePolicies = revocationSkipCertificatePolicies;
    }

    /**
     * Sets maximum accepted freshness for revocation data issued for signature's certificate chain certificates.
     * NULL value is used to disable the check.
     * Default : 0 (revocation data shall be issued after the best-signature-time)
     *
     * @param signatureMaximumRevocationFreshness {@link Long} in milliseconds to evaluate revocation freshness,
     */
    public void setSignatureMaximumRevocationFreshness(Long signatureMaximumRevocationFreshness) {
        this.signatureMaximumRevocationFreshness = signatureMaximumRevocationFreshness;
    }

    /**
     * Sets maximum accepted freshness for revocation data issued for time-stamp's certificate chain certificates.
     * NULL value is used to disable the check.
     * Default : 0 (revocation data shall be issued after the time-stamp's lowest POE)
     * Note : algorithm always ensures that there is a revocation data issued after
     *        the usage time of the time-stamp's certificate
     *
     * @param timestampMaximumRevocationFreshness {@link Long} in milliseconds
     */
    public void setTimestampMaximumRevocationFreshness(Long timestampMaximumRevocationFreshness) {
        this.timestampMaximumRevocationFreshness = timestampMaximumRevocationFreshness;
    }

    /**
     * Sets maximum accepted freshness for revocation data issued for revocation data's
     * certificate chain certificates (CRL or OCSP).
     * NULL value is used to disable the check.
     * Default : 0 (revocation data shall be issued after the best-signature-time)
     * Note : the signature or timestamp constraint takes precedence in case of conflict
     *
     * @param revocationMaximumRevocationFreshness {@link Long} in milliseconds
     */
    public void setRevocationMaximumRevocationFreshness(Long revocationMaximumRevocationFreshness) {
        this.revocationMaximumRevocationFreshness = revocationMaximumRevocationFreshness;
    }

    /**
     * Sets whether the difference between revocation's nextUpdate and thisUpdate fields shall be taken
     * as a maximum acceptable revocation freshness in case no maximum revocation freshness constraint
     * is defined for the given context
     * Default : FALSE (no revocation freshness check is performed when maximum revocation freshness is not defined)
     *
     * @param checkRevocationFreshnessNextUpdate whether revocation freshness should be checked against nextUpdate field
     */
    public void setCheckRevocationFreshnessNextUpdate(boolean checkRevocationFreshnessNextUpdate) {
        this.checkRevocationFreshnessNextUpdate = checkRevocationFreshnessNextUpdate;
    }

    /**
     * This method verifies the validity of the given {@code RevocationToken} using the embedded issuer certificate token
     *
     * @param revocationToken {@link RevocationToken}
     * @return TRUE if the revocation data is acceptable to continue the validation process, FALSE otherwise
     */
    public boolean isAcceptable(RevocationToken<?> revocationToken) {
        return isAcceptable(revocationToken, revocationToken.getIssuerCertificateToken());
    }

    /**
     * This method verifies the validity of the given {@code RevocationToken}
     *
     * @param revocationToken {@link RevocationToken}
     * @param issuerCertificateToken {@link CertificateToken} issued the current revocation
     * @return TRUE if the revocation data is acceptable to continue the validation process, FALSE otherwise
     */
    public boolean isAcceptable(RevocationToken<?> revocationToken, CertificateToken issuerCertificateToken) {
        return isRevocationDataComplete(revocationToken) && isGoodIssuer(revocationToken, issuerCertificateToken) &&
                isConsistent(revocationToken) && isAcceptableSignatureAlgorithm(revocationToken, issuerCertificateToken);
    }

    private boolean isRevocationDataComplete(RevocationToken<?> revocationToken) {
        if (revocationToken.getRelatedCertificate() == null) {
            LOG.warn("The revocation '{}' does not have a related certificate!", revocationToken.getDSSIdAsString());
            return false;
        }
        if (revocationToken.getStatus() == null) {
            LOG.warn("The obtained revocation token '{}' does not contain the certificate status!", revocationToken.getDSSIdAsString());
            return false;
        }
        if (revocationToken.getThisUpdate() == null) {
            LOG.warn("The obtained revocation token '{}' does not contain thisUpdate field!", revocationToken.getDSSIdAsString());
            return false;
        }
        return true;
    }

    private boolean isGoodIssuer(RevocationToken<?> revocationToken, CertificateToken issuerCertificateToken) {
        if (issuerCertificateToken == null) {
            LOG.warn("The issuer certificate is not found for the obtained revocation '{}'!", revocationToken.getDSSIdAsString());
            return false;
        }
        if (RevocationType.OCSP.equals(revocationToken.getRevocationType()) &&
                doesRequireRevocation(issuerCertificateToken) && !hasRevocationAccessPoints(issuerCertificateToken)) {
            LOG.warn("The issuer certificate '{}' of the obtained OCSPToken '{}' requires a revocation data, "
                    + "which is not acceptable due its configuration (no revocation access location points)!",
                    issuerCertificateToken.getDSSIdAsString(), revocationToken.getDSSIdAsString());
            return false;
        }
        if (RevocationType.OCSP.equals(revocationToken.getRevocationType()) &&
                !DSSRevocationUtils.checkIssuerValidAtRevocationProductionTime(revocationToken, issuerCertificateToken)) {
            LOG.warn("The revocation token '{}' has been produced outside the issuer certificate's validity range!",
                    revocationToken.getDSSIdAsString());
            return false;
        }
        return true;
    }

    private boolean doesRequireRevocation(final CertificateToken certificateToken) {
        if (certificateToken.isSelfSigned()) {
            return false;
        }
        if (isTrusted(certificateToken)) {
            return false;
        }
        if (CertificateExtensionsUtils.hasOcspNoCheckExtension(certificateToken)) {
            return false;
        }
        return true;
    }

    private boolean isTrusted(CertificateToken certificateToken) {
        return trustedCertificateSource != null && trustedCertificateSource.isTrusted(certificateToken);
    }

    private boolean hasRevocationAccessPoints(final CertificateToken certificateToken) {
        return Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getCRLAccessUrls(certificateToken)) ||
                Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getOCSPAccessUrls(certificateToken));
    }

    private boolean isConsistent(RevocationToken<?> revocation) {
        final CertificateToken certToken = revocation.getRelatedCertificate();

        if (!isRevocationIssuedAfterCertificateNotBefore(revocation, certToken)) {
            LOG.warn("The revocation '{}' has been produced before the start of the validity of the certificate '{}'!",
                    revocation.getDSSIdAsString(), certToken.getDSSIdAsString());
            return false;
        }
        if (!doesRevocationKnowCertificate(revocation, certToken)) {
            LOG.warn("The revocation '{}' was not issued during the validity period of the certificate! Certificate: {}",
                    revocation.getDSSIdAsString(), certToken.getDSSIdAsString());
            return false;
        }

        LOG.debug("The revocation '{}' is consistent. Certificate: {}", revocation.getDSSIdAsString(), certToken.getDSSIdAsString());
        return true;
    }

    private boolean isRevocationIssuedAfterCertificateNotBefore(RevocationToken<?> revocationToken, CertificateToken certificateToken) {
        return certificateToken.getNotBefore().compareTo(revocationToken.getThisUpdate()) <= 0;
    }

    private boolean doesRevocationKnowCertificate(RevocationToken<?> revocationToken, CertificateToken certificateToken) {
        return revocationInformationAssured(revocationToken, certificateToken) || certHashMatch(revocationToken);
    }

    private boolean revocationInformationAssured(RevocationToken<?> revocationToken,
                                                  CertificateToken certificateToken) {
        Date notAfterRevoc = revocationToken.getThisUpdate();
        Date certNotAfter = certificateToken.getNotAfter();

        Date expiredCertsOnCRL = revocationToken.getExpiredCertsOnCRL();
        if (expiredCertsOnCRL != null) {
            notAfterRevoc = expiredCertsOnCRL;
        }

        Date archiveCutOff = revocationToken.getArchiveCutOff();
        if (archiveCutOff != null) {
            notAfterRevoc = archiveCutOff;
        }

        return certNotAfter.compareTo(notAfterRevoc) >= 0;
    }

    private boolean certHashMatch(RevocationToken<?> revocationToken) {
        return revocationToken.isCertHashPresent() && revocationToken.isCertHashMatch();
    }

    private boolean isAcceptableSignatureAlgorithm(RevocationToken<?> revocationToken, CertificateToken issuerCertificateToken) {
        if (Utils.isCollectionEmpty(acceptableDigestAlgorithms)) {
            LOG.info("No acceptable digest algorithms defined!");
            return false;
        }
        if (Utils.isMapEmpty(acceptableEncryptionAlgorithmKeyLength)) {
            LOG.info("No acceptable encryption algorithms defined!");
            return false;
        }
        SignatureAlgorithm signatureAlgorithm = revocationToken.getSignatureAlgorithm();
        if (signatureAlgorithm == null) {
            LOG.warn("Signature algorithm was not identified for an obtained revocation token '{}'!",
                    revocationToken.getDSSIdAsString());
            return false;
        }
        if (!acceptableDigestAlgorithms.contains(signatureAlgorithm.getDigestAlgorithm())) {
            LOG.warn("The used DigestAlgorithm {} is not acceptable for revocation token '{}'!",
                    signatureAlgorithm.getDigestAlgorithm(), revocationToken.getDSSIdAsString());
            return false;
        }
        Integer encryptionAlgorithmMinKeySize = acceptableEncryptionAlgorithmKeyLength.get(signatureAlgorithm.getEncryptionAlgorithm());
        if (encryptionAlgorithmMinKeySize == null) {
            LOG.warn("The EncryptionAlgorithm {} is not acceptable for revocation token '{}'!",
                    signatureAlgorithm.getEncryptionAlgorithm(), revocationToken.getDSSIdAsString());
            return false;
        }
        int publicKeySize = issuerCertificateToken != null ? DSSPKUtils.getPublicKeySize(issuerCertificateToken.getPublicKey()) : -1;
        if (publicKeySize <= 0) {
            LOG.warn("Key size used to sign revocation token '{}' cannot be identified!",
                    revocationToken.getDSSIdAsString());
            return false;
        }
        if (publicKeySize < encryptionAlgorithmMinKeySize) {
            LOG.warn("The key size '{}' used to sign revocation token '{}' is smaller than minimal acceptable value '{}'!",
                    publicKeySize, revocationToken.getDSSIdAsString(), encryptionAlgorithmMinKeySize);
            return false;
        }
        return true;
    }

    /**
     * Checks and returns whether the revocation check shall be skipped for the given certificate
     *
     * @param certificateToken {@link CertificateToken} to check
     * @return TRUE if the revocation check shall be skipped, FALSE otherwise
     */
    public boolean isRevocationDataSkip(CertificateToken certificateToken) {
        if (trustedCertificateSource != null && trustedCertificateSource.isTrusted(certificateToken)) {
            return true;
        }
        if (certificateToken.isSelfSigned()) {
            return true;
        }
        if (Utils.isCollectionEmpty(revocationSkipCertificateExtensions)) {
            return false;
        }
        CertificateExtensions certificateExtensions = CertificateExtensionsUtils.getCertificateExtensions(certificateToken);
        List<CertificateExtension> allCertificateExtensions = certificateExtensions.getAllCertificateExtensions();
        if (Utils.isCollectionNotEmpty(allCertificateExtensions) &&
                Utils.containsAny(allCertificateExtensions.stream().map(CertificateExtension::getOid).collect(Collectors.toSet()),
                        revocationSkipCertificateExtensions)) {
            return true;
        }
        if (Utils.isCollectionEmpty(revocationSkipCertificatePolicies)) {
            return false;
        }
        CertificatePolicies certificatePolicies = certificateExtensions.getCertificatePolicies();
        if (certificatePolicies != null && Utils.isCollectionNotEmpty(certificatePolicies.getPolicyList()) &&
                Utils.containsAny(certificatePolicies.getPolicyList().stream().map(CertificatePolicy::getOid).collect(Collectors.toSet()),
                revocationSkipCertificatePolicies)) {
            return true;
        }
        return false;
    }

    /**
     * This method verifies if the {@code revocationToken} considered within {@code context} 
     * is fresh enough relatively to the given {@code validationTime}
     * 
     * @param revocationToken {@link RevocationToken} to be validated
     * @param validationTime {@link Date} the target time after which revocation token is expected to be refreshed
     * @param context {@link Context} of the current revocation token's validation process
     * @return TRUE if the revocation token is considered fresh enough, FALSE otherwise
     */
    public boolean isRevocationDataFresh(RevocationToken<?> revocationToken, Date validationTime, Context context) {
        Long maximumRevocationFreshness = getMaximumRevocationFreshness(context);
        if (maximumRevocationFreshness == null) {
            return isRevocationThisUpdateAfterValidationTimeNullConstraint(revocationToken, validationTime);
        }
        return isRevocationThisUpdateAfterValidationTime(revocationToken, validationTime, maximumRevocationFreshness);
    }

    /**
     * This method verifies whether the revocation's thisUpdate time is after the {@code validationTime} minus
     * the acceptable {@code maximumRevocationFreshness}
     *
     * @param revocationToken {@link RevocationToken} to be validated
     * @param validationTime {@link Date}
     * @param maximumRevocationFreshness long
     * @return TRUE if the revocation's thisUpdate is after the validation time minus
     *         the maximum acceptable revocation freshness, FALSE otherwise
     */
    protected boolean isRevocationThisUpdateAfterValidationTime(RevocationToken<?> revocationToken, Date validationTime,
                                                                long maximumRevocationFreshness) {
        long validationDateTime = validationTime.getTime();
        long limit = validationDateTime - maximumRevocationFreshness;

        Date thisUpdate = revocationToken.getThisUpdate();
        return thisUpdate != null && thisUpdate.after(new Date(limit));
    }

    /**
     * This method verifies whether the revocation's thisUpdate time is after the {@code validationTime} minus
     * the difference between nextUpdate and thisUpdate field values
     *
     * @param revocationToken {@link RevocationToken} to be validated
     * @param validationTime {@link Date}
     * @return TRUE if the revocation freshness check succeeds against revocation's nextUpdate, FALSE otherwise
     */
    protected boolean isRevocationThisUpdateAfterValidationTimeNullConstraint(RevocationToken<?> revocationToken,
                                                                              Date validationTime) {
        if (!checkRevocationFreshnessNextUpdate) {
            // no check to be performed
            return true;
        }
        Date nextUpdate = revocationToken.getNextUpdate();
        if (nextUpdate == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No NextUpdate for revocation data with id '{}'. Revocation Freshness check failed.",
                        revocationToken.getDSSIdAsString());
            }
            return false;
        }
        long limit = getDifference(nextUpdate, revocationToken.getThisUpdate());
        return isRevocationThisUpdateAfterValidationTime(revocationToken, validationTime, limit);
    }

    private long getDifference(Date nextUpdate, Date thisUpdate) {
        long nextUpdateTime = nextUpdate == null ? 0 : nextUpdate.getTime();
        long thisUpdateTime = thisUpdate == null ? 0 : thisUpdate.getTime();
        return nextUpdateTime - thisUpdateTime;
    }

    private Long getMaximumRevocationFreshness(Context context) {
        switch (context) {
            case SIGNATURE:
            case COUNTER_SIGNATURE:
            case CERTIFICATE:
                return signatureMaximumRevocationFreshness;
            case TIMESTAMP:
            case EVIDENCE_RECORD:
                return timestampMaximumRevocationFreshness;
            case REVOCATION:
                return revocationMaximumRevocationFreshness;
            default:
                throw new UnsupportedOperationException(
                        String.format("The provided validation context '%s' is not supported!", context));
        }
    }

    /**
     * This method verifies if the revocation data is after the last usage of the certificate.
     * The method is used to ensure the new revocation data has been successfully issued after creation
     * of the last time-stamp with the given certificate
     *
     * @param revocationToken {@link RevocationToken} to be validated
     * @param lastCertificateUsage {@link Date} the last confirmed usage date of the corresponding certificate
     * @return TRUE if the revocation data has been issued after the last certificate usage, FALSE otherwise
     */
    public boolean isRevocationDataAfterLastCertificateUsage(RevocationToken<?> revocationToken, Date lastCertificateUsage) {
        if (lastCertificateUsage == null) {
            // no check to be performed
            return true;
        }
        return isRevocationThisUpdateAfterValidationTime(revocationToken, lastCertificateUsage, 0);
    }

}
