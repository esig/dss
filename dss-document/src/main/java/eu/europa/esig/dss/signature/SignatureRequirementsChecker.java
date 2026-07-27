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
package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;
import eu.europa.esig.dss.spi.validation.SignatureValidationAlerter;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.TimestampTokenVerifier;
import eu.europa.esig.dss.spi.validation.ValidationAlerter;
import eu.europa.esig.dss.spi.validation.status.SignatureStatus;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class is used to verify if the signature can be created according to the provided requirements
 * in a {@code CertificateVerifier} instance
 *
 */
public class SignatureRequirementsChecker {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureRequirementsChecker.class);

    /** CertificateVerifier to be used for certificates validation */
    protected final CertificateVerifier certificateVerifier;

    /** The signature parameters used for signature creation/extension */
    protected final AbstractSignatureParameters<?> signatureParameters;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param signatureParameters {@link AbstractSignatureParameters}
     */
    public SignatureRequirementsChecker(final CertificateVerifier certificateVerifier,
                                        final AbstractSignatureParameters<?> signatureParameters) {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null!");
        Objects.requireNonNull(signatureParameters, "Signature parameters cannot be null!");

        this.certificateVerifier = certificateVerifier;
        this.signatureParameters = signatureParameters;
    }

    /**
     * This method verifies whether the provided certificate token is acceptable for a signature creation
     * against the provided {@code signatureParameters}
     *
     * @param certificateToken {@link CertificateToken}
     */
    public void assertSigningCertificateIsValid(final CertificateToken certificateToken) {
        final ValidationAlerter validationAlerter = initValidationAlerter(certificateToken);
        assertCertificatesAreYetValid(validationAlerter, certificateToken);
        assertCertificatesAreNotExpired(validationAlerter, certificateToken);
        assertCertificatesAreNotRevoked(validationAlerter, certificateToken);
    }

    /**
     * This method verifies a signing certificate for a collection of the given {@code signatures}
     *
     * @param signatures a collection of {@link AdvancedSignature}s to verify signing-certificate for
     */
    public void assertSigningCertificateIsValid(final Collection<AdvancedSignature> signatures) {
        final List<AdvancedSignature> signaturesToValidate = signatures.stream()
                .filter(s -> !isSignatureGeneratedWithoutCertificate(s)).collect(Collectors.toList());
        if (Utils.isCollectionEmpty(signaturesToValidate)) {
            return;
        }

        final ValidationAlerter validationAlerter = initValidationAlerter(signatures);
        assertCertificatesAreYetValid(validationAlerter);
        assertCertificatesAreNotExpired(validationAlerter);
        assertCertificatesAreNotRevoked(validationAlerter);
    }

    private boolean isSignatureGeneratedWithoutCertificate(final AdvancedSignature signature) {
        if (isSigningCertificateIdentified(signature)) {
            return false; // signing-certificate is identified

        } else if (signatureParameters.isGenerateTBSWithoutCertificate()) {
            LOG.debug("Signature with Id '{}' has been generated without certificate or signing-certificate has not been identified. " +
                    "Validity of the signing-certificate is not checked.", signature.getId());
            return true;

        } else {
            throw new IllegalInputException("Signing-certificate token was not found! Unable to verify its validity. " +
                    "Provide signing-certificate or use method #setGenerateTBSWithoutCertificate(true) for signature creation without signing-certificate.");
        }
    }

    private boolean isSigningCertificateIdentified(final AdvancedSignature signature) {
        return signature.getCertificateSource().getNumberOfCertificates() != 0 && signature.getSigningCertificateToken() != null;
    }

    /**
     * This method verifies whether the certificate tokens provided to the validation context are
     * yet valid at the current time
     *
     * @param validationAlerter {@link ValidationAlerter}
     */
    private void assertCertificatesAreYetValid(final ValidationAlerter validationAlerter) {
        assertCertificatesAreYetValid(validationAlerter, null);
    }

    /**
     * This method verifies whether the certificate tokens provided to the validation context are
     * yet valid at the current time
     *
     * @param validationAlerter {@link ValidationAlerter}
     * @param certificateToken {@link CertificateToken} to validate, or NULL for validation of the signatures
     */
    private void assertCertificatesAreYetValid(final ValidationAlerter validationAlerter, CertificateToken certificateToken) {
        if (certificateVerifier.getAlertOnNotYetValidCertificate() == null) {
            LOG.trace("The verification of #certificatesAreYetValid has been skipped.");
            return;
        }

        if (certificateToken != null) {
            validationAlerter.assertCertificateIsYetValid(certificateToken);
        } else {
            validationAlerter.assertAllSignaturesAreYetValid();
        }
    }

    /**
     * This method verifies whether the certificate tokens in the given validation context are yet valid at the current time
     *
     * @param validationAlerter {@link ValidationAlerter}
     */
    private void assertCertificatesAreNotExpired(final ValidationAlerter validationAlerter) {
        assertCertificatesAreNotExpired(validationAlerter, null);
    }

    /**
     * This method verifies whether the certificate tokens in the given validation context are yet valid at the current time
     *
     * @param validationAlerter {@link ValidationAlerter}
     * @param certificateToken {@link CertificateToken} to be validated or NULL in case of signature validation
     */
    private void assertCertificatesAreNotExpired(final ValidationAlerter validationAlerter, CertificateToken certificateToken) {
        if (certificateVerifier.getAlertOnExpiredCertificate() == null) {
            LOG.trace("The verification of #certificatesAreNotExpired has been skipped.");
            return;
        }

        if (certificateToken != null) {
            validationAlerter.assertCertificateNotExpired(certificateToken);
        } else {
            validationAlerter.assertAllSignaturesNotExpired();
        }
    }

    /**
     * Asserts no revoked certificates are present within the given validation context
     *
     * @param validationAlerter {@link ValidationAlerter}
     */
    private void assertCertificatesAreNotRevoked(final ValidationAlerter validationAlerter) {
        assertCertificatesAreNotRevoked(validationAlerter, null);
    }

    /**
     * Asserts no revoked certificates are present within the given validation context
     *
     * @param validationAlerter {@link ValidationAlerter}
     * @param certificateToken {@link CertificateToken} to be validated, or NULL in case of signatures validation
     */
    private void assertCertificatesAreNotRevoked(final ValidationAlerter validationAlerter, CertificateToken certificateToken) {
        if (!signatureParameters.isCheckCertificateRevocation()) {
            return;
        }
        if (certificateVerifier.getAlertOnMissingRevocationData() == null && certificateVerifier.getAlertOnRevokedCertificate() == null) {
            LOG.trace("The verification of #certificatesAreNotRevoked has been skipped.");
            return;
        }

        validationAlerter.assertAllRequiredRevocationDataPresent();
        if (certificateToken != null) {
            validationAlerter.assertCertificateNotRevoked(certificateToken);
        } else {
            validationAlerter.assertAllSignatureCertificatesNotRevoked();
        }
    }

    /**
     * Initializes the validation alerter for certificate validation
     *
     * @param certificateToken {@link CertificateToken} representing the signing-certificate to be validated
     * @return {@link ValidationAlerter}
     */
    protected ValidationAlerter initValidationAlerter(final CertificateToken certificateToken) {
        final SignatureValidationContext validationContext = new SignatureValidationContext(signatureParameters.bLevel().getSigningDate());
        validationContext.initialize(getCertificateVerifier());

        List<CertificateToken> certificateChain = signatureParameters.getCertificateChain();
        if (Utils.isCollectionEmpty(certificateChain)) {
            if (signatureParameters.isCheckCertificateRevocation()) {
                throw new NullPointerException("Certificate chain shall be provided for a revocation check! " +
                        "Please use parameters.setCertificateChain(...) method to provide a certificate chain.");
            }
            certificateChain = Collections.emptyList();
        }
        validationContext.addCertificateTokenForVerification(certificateToken);
        for (CertificateToken certificate : certificateChain) {
            validationContext.addCertificateTokenForVerification(certificate);
        }

        validationContext.validate();

        SignatureValidationAlerter signatureValidationAlerter = new SignatureValidationAlerter(validationContext);
        signatureValidationAlerter.setSigningOperation(SigningOperation.SIGN);
        return signatureValidationAlerter;
    }

    /**
     * Initializes the validation alerter for signature validation
     *
     * @param signatures collection of {@code AdvancedSignature}s to be validated
     * @return {@link ValidationAlerter}
     */
    protected ValidationAlerter initValidationAlerter(final Collection<AdvancedSignature> signatures) {
        final SignatureValidationContext validationContext = new SignatureValidationContext(signatureParameters.bLevel().getSigningDate());
        validationContext.initialize(getCertificateVerifier());

        for (AdvancedSignature signature : signatures) {
            validationContext.addSignatureForVerification(signature);
        }

        validationContext.validate();

        SignatureValidationAlerter signatureValidationAlerter = new SignatureValidationAlerter(validationContext);
        signatureValidationAlerter.setSigningOperation(SigningOperation.EXTEND);
        return signatureValidationAlerter;
    }

    /**
     * Gets CertificateVerifier to be used for validation context verification
     *
     * @return {@link CertificateVerifier}
     */
    protected CertificateVerifier getCertificateVerifier() {
        if (signatureParameters.isCheckCertificateRevocation()) {
            return certificateVerifier;
        }

        // skip revocation check
        final CertificateVerifier offlineCertificateVerifier =
                new CertificateVerifierBuilder(certificateVerifier).buildOfflineCopy();

        RevocationDataVerifier acceptAllRevocationDataVerifier = createAcceptAllRevocationDataVerifier();
        offlineCertificateVerifier.setRevocationDataVerifier(acceptAllRevocationDataVerifier);
        TimestampTokenVerifier timestampTokenVerifier = offlineCertificateVerifier.getTimestampTokenVerifier();
        if (timestampTokenVerifier == null) {
            timestampTokenVerifier = TimestampTokenVerifier.createDefaultTimestampTokenVerifier();
        }
        timestampTokenVerifier.setRevocationDataVerifier(acceptAllRevocationDataVerifier);

        return offlineCertificateVerifier;
    }

    /**
     * This class is used to create a {@code RevocationDataVerifier} returning always
     * a valid revocation status for a certificate.
     * NOTE: This method is used internally for a silent revocation data processing check.
     *
     * @return {@link RevocationDataVerifier}
     */
    private RevocationDataVerifier createAcceptAllRevocationDataVerifier() {
        final RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        revocationDataVerifier.setAcceptRevocationCertificatesWithoutRevocation(true);
        revocationDataVerifier.setAcceptTimestampCertificatesWithoutRevocation(true);
        return revocationDataVerifier;
    }

    /**
     * Verifies whether extension of {@code signatures} to T-level is possible
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertExtendToTLevelPossible(List<AdvancedSignature> signatures) {
        assertTLevelIsHighest(signatures);
        assertHasNoEmbeddedEvidenceRecords(signatures);
    }

    /**
     * Checks whether across {@code signatures} the T-level is highest and T-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertTLevelIsHighest(List<AdvancedSignature> signatures) {
        if (certificateVerifier.getAugmentationAlertOnHigherSignatureLevel() == null) {
            LOG.trace("The verification of #tLevelIsHighest has been skipped.");
            return;
        }
        
        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signatures) {
            checkTLevelIsHighest(signature, status);
        }
        if (!status.isEmpty()) {
            status.setMessage("Error on signature augmentation to T-level.");
            certificateVerifier.getAugmentationAlertOnHigherSignatureLevel().alert(status);
        }
    }

    /**
     * Verifies whether the {@code signature} has maximum B- or T-level
     *
     * @param signature {@link AdvancedSignature} to be verified
     * @param status {@link SignatureStatus} to fill in case of error
     */
    protected void checkTLevelIsHighest(AdvancedSignature signature, SignatureStatus status) {
        if (hasLTLevelOrHigher(signature)) {
            status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");
        }
    }

    /**
     * Checks if the signature has LTA-level
     *
     * @param signature {@link AdvancedSignature} to be validated
     * @return TRUE if the signature has LTA-level, FALSE otherwise
     */
    public boolean hasLTLevelOrHigher(AdvancedSignature signature) {
        return signature.hasLTAProfile() ||
                ((signature.hasLTProfile() || signature.hasCProfile()) && !signature.areAllSelfSignedCertificates() && signature.hasTProfile());
    }

    /**
     * Verifies whether extension of {@code signatures} to LT-level is possible
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertExtendToLTLevelPossible(List<AdvancedSignature> signatures) {
        assertLTLevelIsHighest(signatures);
        assertHasNoEmbeddedEvidenceRecords(signatures);
    }

    /**
     * Checks whether across {@code signatures} the LT-level is highest and LT-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertLTLevelIsHighest(List<AdvancedSignature> signatures) {
        if (certificateVerifier.getAugmentationAlertOnHigherSignatureLevel() == null) {
            LOG.trace("The verification of #ltLevelIsHighest has been skipped.");
            return;
        }
        
        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signatures) {
            checkLTLevelIsHighest(signature, status);
        }
        if (!status.isEmpty()) {
            status.setMessage("Error on signature augmentation to LT-level.");
            certificateVerifier.getAugmentationAlertOnHigherSignatureLevel().alert(status);
        }
    }

    /**
     * Verifies whether the {@code signature} has maximum B-, T- or LT-level
     *
     * @param signature {@link AdvancedSignature} to be verified
     * @param status {@link SignatureStatus} to fill in case of error
     */
    protected void checkLTLevelIsHighest(AdvancedSignature signature, SignatureStatus status) {
        if (hasLTALevelOrHigher(signature)) {
            status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");
        }
    }

    /**
     * Checks if the signature has LTA-level
     *
     * @param signature {@link AdvancedSignature} to be validated
     * @return TRUE if the signature has LTA-level, FALSE otherwise
     */
    public boolean hasLTALevelOrHigher(AdvancedSignature signature) {
        return signature.hasLTAProfile();
    }

    /**
     * Checks whether across {@code signatures} the corresponding certificate chains require
     * revocation data for LT-level augmentation
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertCertificateChainValidForLTLevel(List<AdvancedSignature> signatures) {
        assertCertificateChainValid(signatures, "LT");
    }

    /**
     * Checks whether across {@code signatures} the corresponding certificate chains require
     * revocation data for C-level augmentation
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertCertificateChainValidForCLevel(List<AdvancedSignature> signatures) {
        assertCertificateChainValid(signatures, "C");
    }

    /**
     * Checks whether across {@code signatures} the corresponding certificate chains require
     * revocation data for XL-level augmentation
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertCertificateChainValidForXLLevel(List<AdvancedSignature> signatures) {
        assertCertificateChainValid(signatures, "XL");
    }

    private void assertCertificateChainValid(List<AdvancedSignature> signatures, String targetLevel) {
        assertCertificatePresent(signatures, targetLevel);
        assertCertificatesAreNotSelfSigned(signatures, targetLevel);
    }

    private void assertCertificatePresent(List<AdvancedSignature> signatures, String targetLevel) {
        if (certificateVerifier.getAugmentationAlertOnSignatureWithoutCertificates() == null) {
            LOG.trace("The verification of #certificatePresent has been skipped.");
            return;
        }
        
        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signatures) {
            if (signature.getCertificateSource().getNumberOfCertificates() == 0) {
                status.addRelatedTokenAndErrorMessage(signature, "The signature does not contain certificates.");
            }
        }
        if (!status.isEmpty()) {
            status.setMessage(String.format("Error on signature augmentation to %s-level.", targetLevel));
            certificateVerifier.getAugmentationAlertOnSignatureWithoutCertificates().alert(status);
        }
    }

    private void assertCertificatesAreNotSelfSigned(List<AdvancedSignature> signatures, String targetLevel) {
        if (certificateVerifier.getAugmentationAlertOnSelfSignedCertificateChains() == null) {
            LOG.trace("The verification of #certificatesAreNotSelfSigned has been skipped.");
            return;
        }
        
        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signatures) {
            if (signature.areAllSelfSignedCertificates()) {
                status.addRelatedTokenAndErrorMessage(signature, "The signature contains only self-signed certificate chains.");
            }
        }
        if (!status.isEmpty()) {
            status.setMessage(String.format("Error on signature augmentation to %s-level.", targetLevel));
            certificateVerifier.getAugmentationAlertOnSelfSignedCertificateChains().alert(status);
        }
    }

    /**
     * Verifies whether extension of {@code signatures} to C-level is possible
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertExtendToCLevelPossible(List<AdvancedSignature> signatures) {
        assertCLevelIsHighest(signatures);
        assertHasNoEmbeddedEvidenceRecords(signatures);
    }

    /**
     * Checks whether across {@code signatures} the C-level is highest and C-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertCLevelIsHighest(List<AdvancedSignature> signatures) {
        if (certificateVerifier.getAugmentationAlertOnHigherSignatureLevel() == null) {
            LOG.trace("The verification of #cLevelIsHighest has been skipped.");
            return;
        }
        
        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signatures) {
            checkCLevelIsHighest(signature, status);
        }
        if (!status.isEmpty()) {
            status.setMessage("Error on signature augmentation to C-level.");
            certificateVerifier.getAugmentationAlertOnHigherSignatureLevel().alert(status);
        }
    }

    /**
     * Verifies whether the {@code signature} has maximum B-, T- or LT-level
     *
     * @param signature {@link AdvancedSignature} to be verified
     * @param status {@link SignatureStatus} to fill in case of error
     */
    protected void checkCLevelIsHighest(AdvancedSignature signature, SignatureStatus status) {
        if (hasXLevelOrHigher(signature)) {
            status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");
        }
    }

    /**
     * Checks if the signature has LTA-level
     *
     * @param signature {@link AdvancedSignature} to be validated
     * @return TRUE if the signature has LTA-level, FALSE otherwise
     */
    public boolean hasXLevelOrHigher(AdvancedSignature signature) {
        return (signature.hasXProfile() || signature.hasAProfile() ||
                (signature.hasXLProfile() && !signature.areAllSelfSignedCertificates() && signature.hasTProfile()));
    }

    /**
     * Verifies whether extension of {@code signatures} to X-level is possible
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertExtendToXLevelPossible(List<AdvancedSignature> signatures) {
        assertXLevelIsHighest(signatures);
        assertHasNoEmbeddedEvidenceRecords(signatures);
    }

    /**
     * Checks whether across {@code signatures} the X-level is highest and X-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertXLevelIsHighest(List<AdvancedSignature> signatures) {
        if (certificateVerifier.getAugmentationAlertOnHigherSignatureLevel() == null) {
            LOG.trace("The verification of #xLevelIsHighest has been skipped.");
            return;
        }
        
        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signatures) {
            checkXLevelIsHighest(signature, status);
        }
        if (!status.isEmpty()) {
            status.setMessage("Error on signature augmentation to X-level.");
            certificateVerifier.getAugmentationAlertOnHigherSignatureLevel().alert(status);
        }
    }

    /**
     * Verifies whether the {@code signature} has maximum B-, T- or LT-level
     *
     * @param signature {@link AdvancedSignature} to be verified
     * @param status {@link SignatureStatus} to fill in case of error
     */
    protected void checkXLevelIsHighest(AdvancedSignature signature, SignatureStatus status) {
        if (hasXLLevelOrHigher(signature)) {
            status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");
        }
    }

    /**
     * Checks if the signature has LTA-level
     *
     * @param signature {@link AdvancedSignature} to be validated
     * @return TRUE if the signature has LTA-level, FALSE otherwise
     */
    public boolean hasXLLevelOrHigher(AdvancedSignature signature) {
        return signature.hasAProfile() || (signature.hasXLProfile() && !signature.areAllSelfSignedCertificates() && signature.hasTProfile() && signature.hasXProfile());
    }

    /**
     * Verifies whether extension of {@code signatures} to XL-level is possible
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertExtendToXLLevelPossible(List<AdvancedSignature> signatures) {
        assertXLLevelIsHighest(signatures);
        assertHasNoEmbeddedEvidenceRecords(signatures);
    }

    /**
     * Checks whether across {@code signatures} the XL-level is highest and XL-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertXLLevelIsHighest(List<AdvancedSignature> signatures) {
        if (certificateVerifier.getAugmentationAlertOnHigherSignatureLevel() == null) {
            LOG.trace("The verification of #xlLevelIsHighest has been skipped.");
            return;
        }
        
        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signatures) {
            checkXLLevelIsHighest(signature, status);
        }
        if (!status.isEmpty()) {
            status.setMessage("Error on signature augmentation to XL-level.");
            certificateVerifier.getAugmentationAlertOnHigherSignatureLevel().alert(status);
        }
    }

    /**
     * Verifies whether the {@code signature} has maximum X-level
     *
     * @param signature {@link AdvancedSignature} to be verified
     * @param status {@link SignatureStatus} to fill in case of error
     */
    protected void checkXLLevelIsHighest(AdvancedSignature signature, SignatureStatus status) {
        if (hasALevelOrHigher(signature)) {
            status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");
        }
    }

    /**
     * Checks if the signature has A-level
     *
     * @param signature {@link AdvancedSignature} to be validated
     * @return TRUE if the signature has A-level, FALSE otherwise
     */
    public boolean hasALevelOrHigher(AdvancedSignature signature) {
        return hasLTALevelOrHigher(signature);
    }

    /**
     * Verifies whether extension of {@code signatures} to LTA-level is possible
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertExtendToLTALevelPossible(List<AdvancedSignature> signatures) {
        assertHasNoEmbeddedEvidenceRecords(signatures);
    }

    /**
     * Checks whether across {@code signatures} the T-level is highest and T-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertHasNoEmbeddedEvidenceRecords(List<AdvancedSignature> signatures) {
        if (certificateVerifier.getAugmentationAlertOnHigherSignatureLevel() == null) {
            LOG.trace("The verification of #hasEmbeddedEvidenceRecords has been skipped.");
            return;
        }

        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signatures) {
            checkHasEmbeddedEvidenceRecords(signature, status);
        }
        if (!status.isEmpty()) {
            status.setMessage("Error on signature augmentation");
            certificateVerifier.getAugmentationAlertOnHigherSignatureLevel().alert(status);
        }
    }

    /**
     * Verifies whether the {@code signature} has an embedded evidence record
     *
     * @param signature {@link AdvancedSignature} to be verified
     * @param status {@link SignatureStatus} to fill in case of error
     */
    protected void checkHasEmbeddedEvidenceRecords(AdvancedSignature signature, SignatureStatus status) {
        if (hasEmbeddedEvidenceRecords(signature)) {
            status.addRelatedTokenAndErrorMessage(signature, "The signature is preserved by an embedded evidence record.");
        }
    }

    /**
     * Checks if the signature has embedded evidence records
     *
     * @param signature {@link AdvancedSignature} to be validated
     * @return TRUE if the signature has an embedded evidence record, FALSE otherwise
     */
    public boolean hasEmbeddedEvidenceRecords(AdvancedSignature signature) {
        return Utils.isCollectionNotEmpty(signature.getEmbeddedEvidenceRecords());
    }

    /**
     * Verifies cryptographical validity of the signatures
     *
     * @param signatures a collection of {@link AdvancedSignature}s
     */
    public void assertSignaturesValid(final Collection<AdvancedSignature> signatures) {
        if (certificateVerifier.getAlertOnInvalidSignature() == null) {
            LOG.trace("The verification of #signaturesValid has been skipped.");
            return;
        }
        
        final List<AdvancedSignature> signaturesToValidate = signatures.stream()
                .filter(s -> !isSignatureGeneratedWithoutCertificate(s)).collect(Collectors.toList());
        if (Utils.isCollectionEmpty(signaturesToValidate)) {
            return;
        }

        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signaturesToValidate) {
            final SignatureCryptographicVerification signatureCryptographicVerification = signature.getSignatureCryptographicVerification();
            if (!signatureCryptographicVerification.isSignatureValid()) {
                final String errorMessage = signatureCryptographicVerification.getErrorMessage();
                status.addRelatedTokenAndErrorMessage(signature, "Cryptographic signature verification has failed"
                        + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
            }
        }
        if (!status.isEmpty()) {
            status.setMessage("Error on signature augmentation");
            certificateVerifier.getAlertOnInvalidSignature().alert(status);
        }
    }

}
