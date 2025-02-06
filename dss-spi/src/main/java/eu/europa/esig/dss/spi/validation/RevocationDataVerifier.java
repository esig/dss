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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;
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

        DEFAULT_ENCRYPTION_ALGORITHMS_KEY_LENGTH_MAP = new EnumMap<>(EncryptionAlgorithm.class);
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
     * A collection of revocation data to be processed. This is a local variable used to be defined
     * by a SignatureValidationContext, calling the class
     */
    private Collection<RevocationToken<?>> processedRevocations;

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
     * This variable indicates whether timestamp certificates without revocation data should be accepted
     */
    private boolean acceptTimestampCertificatesWithoutRevocation;

    /**
     * This variable indicates whether revocation certificates without revocation data should be accepted
     */
    private boolean acceptRevocationCertificatesWithoutRevocation;

    /**
     * Verifies whether a given certificate token is a trust anchor at the control time
     */
    private TrustAnchorVerifier trustAnchorVerifier;

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
            // #acceptRevocationIssuersWithoutRevocation is false
            return revocationDataVerifier;
        } catch (Exception e) {
            throw new DSSException(String.format(
                    "Unable to instantiate default RevocationDataVerifier. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Gets a collection of processed revocations, when present.
     * This method is used internally during a {@code eu.europa.esig.dss.validation.SignatureValidationContext} execution,
     * to verify presence of the collection of processed revocation data
     *
     * @return a collection of {@link RevocationToken}s
     */
    protected Collection<RevocationToken<?>> getProcessedRevocations() {
        return processedRevocations;
    }

    /**
     * This method sets a collection of processed revocation tokens, for validation of timestamp's certificate chain.
     * Note : This method is used internally during a {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *        initialization, in order to provide the same revocation data as the one used within
     *        the certificate validation process.
     * @param processedRevocations a collection of {@link RevocationToken}s
     */
    protected void setProcessedRevocations(Collection<RevocationToken<?>> processedRevocations) {
        this.processedRevocations = processedRevocations;
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
     * This method sets whether a timestamp certificate without a valid revocation data should be accepted by the verifier
     *
     * @param acceptTimestampCertificatesWithoutRevocation whether a timestamp certificate without revocation data should be accepted
     */
    public void setAcceptTimestampCertificatesWithoutRevocation(boolean acceptTimestampCertificatesWithoutRevocation) {
        this.acceptTimestampCertificatesWithoutRevocation = acceptTimestampCertificatesWithoutRevocation;
    }

    /**
     * This method sets whether a revocation certificate without a valid revocation data should be accepted by the verifier
     *
     * @param acceptRevocationCertificatesWithoutRevocation whether a revocation certificate without revocation data should be accepted
     */
    public void setAcceptRevocationCertificatesWithoutRevocation(boolean acceptRevocationCertificatesWithoutRevocation) {
        this.acceptRevocationCertificatesWithoutRevocation = acceptRevocationCertificatesWithoutRevocation;
    }

    /**
     * Gets a trust anchor verifier. This method is used internally within {@code eu.europa.esig.dss.validation.SignatureValidationContext}
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
     * This method verifies the validity of the given {@code RevocationToken} using the embedded
     * issuer certificate token at the current time
     *
     * @param revocationToken {@link RevocationToken}
     * @return TRUE if the revocation data is acceptable to continue the validation process, FALSE otherwise
     */
    public boolean isAcceptable(RevocationToken<?> revocationToken) {
        return isAcceptable(revocationToken, new Date());
    }

    /**
     * This method verifies the validity of the given {@code RevocationToken} at the given {@code controlTime}
     * using the embedded issuer certificate token
     *
     * @param revocationToken {@link RevocationToken}
     * @param controlTime {@link Date}
     * @return TRUE if the revocation data is acceptable to continue the validation process, FALSE otherwise
     */
    public boolean isAcceptable(RevocationToken<?> revocationToken, Date controlTime) {
        return isAcceptable(revocationToken, revocationToken.getIssuerCertificateToken(), controlTime);
    }

    /**
     * This method verifies the validity of the given {@code RevocationToken} at the current time
     *
     * @param revocationToken {@link RevocationToken}
     * @param issuerCertificateToken {@link CertificateToken} issued the current revocation
     * @return TRUE if the revocation data is acceptable to continue the validation process, FALSE otherwise
     */
    public boolean isAcceptable(RevocationToken<?> revocationToken, CertificateToken issuerCertificateToken) {
        return isAcceptable(revocationToken, issuerCertificateToken, new Date());
    }

    /**
     * This method verifies the validity of the given {@code RevocationToken} at {@code controlTime}
     *
     * @param revocationToken {@link RevocationToken}
     * @param issuerCertificateToken {@link CertificateToken} issued the current revocation
     * @param controlTime {@link Date}
     * @return TRUE if the revocation data is acceptable to continue the validation process, FALSE otherwise
     */
    public boolean isAcceptable(RevocationToken<?> revocationToken, CertificateToken issuerCertificateToken, Date controlTime) {
        return isAcceptable(revocationToken, issuerCertificateToken, Collections.emptyList(), controlTime);
    }

    /**
     * This method verifies the validity of the given {@code RevocationToken} at {@code controlTime}
     *
     * @param revocationToken {@link RevocationToken}
     * @param issuerCertificateToken {@link CertificateToken} issued the current revocation
     * @param certificateChain a list of {@link CertificateToken}s, representing a certificate chain of the issuer
     * @param controlTime {@link Date}
     * @return TRUE if the revocation data is acceptable to continue the validation process, FALSE otherwise
     */
    public boolean isAcceptable(RevocationToken<?> revocationToken, CertificateToken issuerCertificateToken,
                                List<CertificateToken> certificateChain, Date controlTime) {
        return isRevocationTokenValid(revocationToken) && isRevocationDataComplete(revocationToken)
                && isGoodIssuer(revocationToken, issuerCertificateToken, controlTime)
                && isCertificateChainValid(certificateChain, controlTime, Context.REVOCATION) && isConsistent(revocationToken)
                && isAcceptableSignatureAlgorithm(revocationToken, issuerCertificateToken);
    }

    /**
     * Verifies whether the revocation token is cryptographically valid
     *
     * @param revocationToken {@link RevocationToken} to be verified
     * @return TRUE if the revocation token is valid, FALSE otherwise
     */
    protected boolean isRevocationTokenValid(RevocationToken<?> revocationToken) {
        if (!revocationToken.isValid()) {
            LOG.warn("The revocation token '{}' is not valid : {}!", revocationToken.getDSSIdAsString(), revocationToken.getInvalidityReason());
            return false;
        }
        return true;
    }

    /**
     * Verifies whether the revocation token contains all required data
     *
     * @param revocationToken {@link RevocationToken} to be verifies
     * @return TRUE if the revocation token is complete, FALSE otherwise
     */
    protected boolean isRevocationDataComplete(RevocationToken<?> revocationToken) {
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

    /**
     * Verifies validity if the {@code issuerCertificateToken} of {@code revocationToken}
     *
     * @param revocationToken {@link RevocationToken} concerned revocation token
     * @param issuerCertificateToken {@link CertificateToken} issued the revocation token
     * @param controlTime {@link Date} validation time
     * @return TRUE if the issuer certificate token is valid at the control time, FALSE otherwise
     */
    protected boolean isGoodIssuer(RevocationToken<?> revocationToken, CertificateToken issuerCertificateToken, Date controlTime) {
        if (issuerCertificateToken == null) {
            LOG.warn("The issuer certificate is not found for the obtained revocation '{}'!", revocationToken.getDSSIdAsString());
            return false;
        }
        if (RevocationType.OCSP.equals(revocationToken.getRevocationType()) &&
                !DSSRevocationUtils.checkIssuerValidAtRevocationProductionTime(revocationToken, issuerCertificateToken)) {
            LOG.warn("The revocation token '{}' has been produced outside the issuer certificate's validity range!",
                    revocationToken.getDSSIdAsString());
            return false;
        }
        if (!isCertificateValid(issuerCertificateToken, controlTime)) {
            return false;
        }
        return true;
    }

    /**
     * Verifies whether the revocation token is consistent
     *
     * @param revocation {@link RevocationToken} to be verified
     * @return TRUE if the revocation token is consistent, FALSE otherwise
     */
    protected boolean isConsistent(RevocationToken<?> revocation) {
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

    private boolean revocationInformationAssured(RevocationToken<?> revocationToken, CertificateToken certificateToken) {
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

    /**
     * Verifies validity of the used signature algorithm on revocation data creation is still valid according
     * to the specified cryptographic constraints.
     *
     * @param revocationToken {@link RevocationToken} to be verified
     * @param issuerCertificateToken {@link CertificateToken} issued the revocation token
     * @return TRUE if the signature algorithm used on revocation token creation, FALSE otherwise
     */
    protected boolean isAcceptableSignatureAlgorithm(RevocationToken<?> revocationToken, CertificateToken issuerCertificateToken) {
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
     * Checks and returns whether the revocation check shall be skipped for the given certificate at the current time
     *
     * @param certificateToken {@link CertificateToken} to check
     * @return TRUE if the revocation check shall be skipped, FALSE otherwise
     */
    public boolean isRevocationDataSkip(CertificateToken certificateToken) {
        return isRevocationDataSkip(certificateToken, new Date());
    }

    /**
     * Checks and returns whether the revocation check shall be skipped for the given certificate at the {@code controlTime}
     *
     * @param certificateToken {@link CertificateToken} to check
     * @param controlTime {@link Date} the validation time
     * @return TRUE if the revocation check shall be skipped, FALSE otherwise
     */
    public boolean isRevocationDataSkip(CertificateToken certificateToken, Date controlTime) {
        if (isTrustedAtTime(certificateToken, controlTime)) {
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
     * This method verifies whether the {@code certificateToken} is trusted at {@code controlTime}
     *
     * @param certificateToken {@link CertificateToken} to check
     * @param controlTime {@link Date} the validation time
     * @return TRUE if the certificate is trusted at the given time, FALSE otherwise
     */
    protected boolean isTrustedAtTime(CertificateToken certificateToken, Date controlTime) {
        final TrustAnchorVerifier currentTrustAnchorVerifier = getTrustAnchorVerifier();
        if (currentTrustAnchorVerifier == null) {
            LOG.warn("TrustAnchorVerifier is not defined! None of the certificates will be considered as a trust anchor.");
            return false;
        }
        return currentTrustAnchorVerifier.isTrustedAtTime(certificateToken, controlTime, Context.REVOCATION);
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
     * This method verifies whether a certificate was not revoked at {@code controlTime}
     *
     * @param revocationToken {@link RevocationToken} to check
     * @param controlTime {@link Date} time to check at
     * @return TRUE if the certificate was not revoked at control time, FALSE otherwise
     */
    public boolean checkCertificateNotRevoked(RevocationToken<?> revocationToken, Date controlTime) {
        return revocationToken.getStatus().isKnown() &&
                (!revocationToken.getStatus().isRevoked() || controlTime.before(revocationToken.getRevocationDate()));
    }

    /**
     * Verifies whether the {@code controlTime} is within revocation data's thisUpdate and nextUpdate times
     *
     * @param revocationToken {@link RevocationToken} to validate
     * @param date {@link Date} validation time
     * @return TRUE if the control time is within thisUpdate and nextUpdate times, FALSE otherwise
     */
    public boolean isAfterThisUpdateAndBeforeNextUpdate(RevocationToken<?> revocationToken, Date date) {
        Date thisUpdate = revocationToken.getThisUpdate();
        Date nextUpdate = revocationToken.getNextUpdate();
        return thisUpdate != null && date.compareTo(thisUpdate) >= 0 && (nextUpdate == null || date.compareTo(nextUpdate) <= 0);
    }

    /**
     * This method verifies whether the certificate chain is valid at control time
     *
     * @param certificateTokenChain a list of {@link CertificateToken}s
     * @param controlTime {@link Date} validation time
     * @param context {@link Context} validation context
     * @return TRUE if the certificate chain is valid at control time, FALSE otherwise
     */
    public boolean isCertificateChainValid(List<CertificateToken> certificateTokenChain, Date controlTime, Context context) {
        if (isAcceptCertificatesWithoutRevocation(context)) {
            return true;
        }
        for (CertificateToken certificateToken : certificateTokenChain) {
            if (certificateToken.isSelfSigned() || isTrustedAtTime(certificateToken, controlTime)) {
                break;
            }
            if (!certificateToken.isValid()) {
                LOG.warn("The certificate '{}' is cryptographically invalid!", certificateToken.getDSSIdAsString());
                return false;
            }
            if (!isCertificateValid(certificateToken, controlTime)) {
                return false;
            }
        }
        return true;
    }

    private boolean isAcceptCertificatesWithoutRevocation(Context context) {
        return (Context.TIMESTAMP == context && acceptTimestampCertificatesWithoutRevocation) ||
                (Context.REVOCATION == context && acceptRevocationCertificatesWithoutRevocation);
    }

    /**
     * Verifies if the certificate is valid
     *
     * @param certificateToken {@link CertificateToken}
     * @param controlTime {@link Date}
     * @return TRUE if the certificate token is valid, FALSE otherwise
     */
    protected boolean isCertificateValid(CertificateToken certificateToken, Date controlTime) {
        if (!isRevocationDataSkip(certificateToken, controlTime)) {
            if (!hasRevocationAccessPoints(certificateToken)) {
                LOG.warn("The certificate '{}' requires a revocation data, " +
                                "which is not acceptable due its configuration (no revocation access location points)!",
                        certificateToken.getDSSIdAsString());
                return false;
            }
            if (!isCertificateNotRevoked(certificateToken, controlTime)) {
                LOG.warn("The certificate '{}' does not contain a valid revocation data information!",
                        certificateToken.getDSSIdAsString());
                return false;
            }
        }
        return true;
    }

    private boolean hasRevocationAccessPoints(final CertificateToken certificateToken) {
        return Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getCRLAccessUrls(certificateToken)) ||
                Utils.isCollectionNotEmpty(CertificateExtensionsUtils.getOCSPAccessUrls(certificateToken));
    }

    /**
     * This method verifies whether a certificate token is not revoked at control time
     *
     * @param certificateToken {@link CertificateToken} to validated
     * @param controlTime {@link Date} validation time
     * @return TRUE if the certificate token is valid at control time, FALSE otherwise
     */
    protected boolean isCertificateNotRevoked(CertificateToken certificateToken, Date controlTime) {
        List<RevocationToken<?>> revocationData = getRelatedRevocationTokens(certificateToken);
        if (Utils.isCollectionNotEmpty(revocationData)) {
            for (RevocationToken<?> revocationToken : revocationData) {
                if (isAcceptable(revocationToken, controlTime) && checkCertificateNotRevoked(revocationToken, controlTime)) {
                    return true;
                }
            }
        }
        LOG.warn("The certificate '{}' is not known to be not revoked!", certificateToken.getDSSIdAsString());
        return false;
    }

    private List<RevocationToken<?>> getRelatedRevocationTokens(CertificateToken certificateToken) {
        if (Utils.isCollectionEmpty(processedRevocations)) {
            return Collections.emptyList();
        }
        List<RevocationToken<?>> result = new ArrayList<>();
        for (RevocationToken<?> revocationToken : processedRevocations) {
            if (Utils.areStringsEqual(certificateToken.getDSSIdAsString(), revocationToken.getRelatedCertificateId())) {
                result.add(revocationToken);
            }
        }
        return result;
    }

}
