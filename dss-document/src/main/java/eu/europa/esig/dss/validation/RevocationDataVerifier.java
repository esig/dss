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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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

    /**
     * The trusted certificate source is used to accept trusted OCSPToken's certificate issuers
     */
    protected ListCertificateSource trustedListCertificateSource;

    /**
     * A collection of Digest Algorithms to accept from CRL/OCSP responders.
     *
     * NOTE : revocation tokens created with digest algorithms other than listed in this collection will be skipped.
     *
     * DEFAULT : collection of algorithms is synchronized with ETSI 119 312 V1.4.2
     */
    protected Collection<DigestAlgorithm> acceptableDigestAlgorithms;

    /**
     * Map of acceptable Encryption Algorithms with a corresponding minimal acceptable key length for each algorithm.
     *
     * NOTE : revocation tokens created with encryption algorithms other than listed in this map or
     *        with a key size smaller than defined in the map will be skipped.
     *
     * DEFAULT : collection of algorithms is synchronized with ETSI 119 312 V1.4.2
     */
    protected Map<EncryptionAlgorithm, Integer> acceptableEncryptionAlgorithmKeyLength;

    /**
     * Default constructor
     */
    private RevocationDataVerifier() {
    }

    /**
     * This method is used to instantiate a new {@code RevocationDataVerifier}, using the default validation constraints
     * (synchronized with default validation policy).
     *
     * @return {@link RevocationDataVerifier}
     */
    public static RevocationDataVerifier createDefaultRevocationDataVerifier() {
        try {
            final ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
            return createRevocationDataVerifierFromPolicy(validationPolicy);
        } catch (Exception e) {
            throw new DSSException(String.format(
                    "Unable to instantiate default RevocationDataVerifier. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * This method is used to instantiate a {@code RevocationDataVerifier} from a given {@code ValidationPolicy}
     * in order to synchronize the validation constraints at the current validation time.
     *
     * @param validationPolicy {@link ValidationPolicy} to be used
     * @return {@link RevocationDataVerifier}
     */
    public static RevocationDataVerifier createRevocationDataVerifierFromPolicy(final ValidationPolicy validationPolicy) {
        return createRevocationDataVerifierFromPolicyWithTime(validationPolicy, new Date());
    }

    /**
     * This method is used to instantiate a {@code RevocationDataVerifier} from a given {@code ValidationPolicy}
     * in order to synchronize the validation constraints with a provided {@code validationTime}.
     *
     * @param validationPolicy {@link ValidationPolicy} to be used
     * @param validationTime {@link Date} the target validation time
     * @return {@link RevocationDataVerifier}
     */
    public static RevocationDataVerifier createRevocationDataVerifierFromPolicyWithTime(ValidationPolicy validationPolicy, Date validationTime) {
        final RevocationDataVerifier revocationDataVerifier = new RevocationDataVerifier();
        List<DigestAlgorithm> acceptableDigestAlgorithms;
        Map<EncryptionAlgorithm, Integer> acceptableEncryptionAlgorithms;

        final CryptographicConstraintWrapper constraint = getRevocationCryptographicConstraints(validationPolicy);
        if (constraint != null && Level.FAIL.equals(constraint.getLevel())) {
            acceptableDigestAlgorithms = constraint.getReliableDigestAlgorithmsAtTime(validationTime);
            acceptableEncryptionAlgorithms = constraint.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(validationTime);
        } else {
            LOG.info("No enforced cryptographic constraints have been found in the provided validation policy. Accept all cryptographic algorithms.");
            acceptableDigestAlgorithms = Arrays.asList(DigestAlgorithm.values());
            acceptableEncryptionAlgorithms = new HashMap<>();
            for (EncryptionAlgorithm encryptionAlgorithm : EncryptionAlgorithm.values()) {
                acceptableEncryptionAlgorithms.put(encryptionAlgorithm, 0);
            }
        }
        revocationDataVerifier.setAcceptableDigestAlgorithms(acceptableDigestAlgorithms);
        revocationDataVerifier.setAcceptableEncryptionAlgorithmKeyLength(acceptableEncryptionAlgorithms);
        return revocationDataVerifier;
    }

    private static CryptographicConstraintWrapper getRevocationCryptographicConstraints(ValidationPolicy validationPolicy) {
        final CryptographicConstraint cryptographicConstraint = validationPolicy.getSignatureCryptographicConstraint(Context.REVOCATION);
        return cryptographicConstraint != null ? new CryptographicConstraintWrapper(cryptographicConstraint) : null;
    }

    /**
     * Sets a trusted certificate source in order to accept trusted OCSPToken's certificate issuers.
     *
     * NOTE : This method is used internally during a {@code eu.europa.esig.dss.validation.SignatureValidationContext}
     *        initialization, in order to provide the same trusted source as the one used within
     *        a {@code eu.europa.esig.dss.validation.CertificateVerifier}.
     *
     * @param trustedListCertificateSource {@link ListCertificateSource}
     */
    void setTrustedCertificateSource(ListCertificateSource trustedListCertificateSource) {
        this.trustedListCertificateSource = trustedListCertificateSource;
    }

    /**
     * Sets a collection of Digest Algorithms for acceptance.
     * If a revocation token is signed with an algorithm other than listed in the collection, the token will be skipped.
     *
     * DEFAULT : collection of algorithms is synchronized with ETSI 119 312 V1.4.2
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
     *
     * DEFAULT : collection of algorithms is synchronized with ETSI 119 312 V1.4.2
     *
     * @param acceptableEncryptionAlgorithmKeyLength a map of {@link EncryptionAlgorithm}s and
     *                                               their corresponding minimal supported key lengths
     */
    public void setAcceptableEncryptionAlgorithmKeyLength(Map<EncryptionAlgorithm, Integer> acceptableEncryptionAlgorithmKeyLength) {
        Objects.requireNonNull(acceptableEncryptionAlgorithmKeyLength, "Map of Encryption Algorithms for acceptance cannot be null!");
        this.acceptableEncryptionAlgorithmKeyLength = acceptableEncryptionAlgorithmKeyLength;
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
        if (DSSASN1Utils.hasIdPkixOcspNoCheckExtension(certificateToken)) {
            return false;
        }
        return true;
    }

    private boolean isTrusted(CertificateToken certificateToken) {
        return trustedListCertificateSource != null && trustedListCertificateSource.isTrusted(certificateToken);
    }

    private boolean hasRevocationAccessPoints(final CertificateToken certificateToken) {
        if (Utils.isCollectionNotEmpty(DSSASN1Utils.getOCSPAccessLocations(certificateToken))) {
            return true;
        }
        if (Utils.isCollectionNotEmpty(DSSASN1Utils.getCrlUrls(certificateToken))) {
            return true;
        }
        return false;
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

}
