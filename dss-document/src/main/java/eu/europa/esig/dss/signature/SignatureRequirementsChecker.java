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
package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.status.SignatureStatus;
import eu.europa.esig.dss.spi.validation.status.TokenStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
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
        assertCertificatesAreYetValid(certificateToken);
        assertSigningCertificateIsNotExpired(certificateToken);
        assertCertificatesAreNotRevoked(certificateToken);
    }

    /**
     * This method verifies a signing certificate of the given {@code signature}
     *
     * @param signature {@link AdvancedSignature} to verify
     */
    public void assertSigningCertificateIsValid(final AdvancedSignature signature) {
        assertSigningCertificateIsValid(Collections.singletonList(signature));
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

        final List<CertificateToken> signingCertificates = signaturesToValidate.stream()
                .map(AdvancedSignature::getSigningCertificateToken).collect(Collectors.toList());

        assertCertificatesAreYetValid(signingCertificates, false);
        assertCertificatesAreNotExpired(signingCertificates, false);
        assertCertificatesAreNotRevoked(signatures);
    }

    private boolean isSignatureGeneratedWithoutCertificate(final AdvancedSignature signature) {
        if (signatureParameters.isGenerateTBSWithoutCertificate() && signature.getCertificateSource().getNumberOfCertificates() == 0) {
            LOG.debug("Signature with Id '{}' has been generated without certificate. " +
                            "Validity of the signing-certificate is not checked.", signature.getId());
            return true;
        }
        return false;
    }

    /**
     * This method verifies whether the given {@code CertificateToken} is yet valid at the current time
     *
     * @param certificateToken {@link CertificateToken}
     */
    private void assertCertificatesAreYetValid(final CertificateToken certificateToken) {
        assertCertificatesAreYetValid(Collections.singletonList(certificateToken), true);
    }

    /**
     * This method verifies whether the given certificate tokens are yet valid at the current time
     *
     * @param certificateTokens a collection of {@link CertificateToken}s
     * @param signing defines whether the validation is performed on signing or augmentation process
     */
    private void assertCertificatesAreYetValid(final Collection<CertificateToken> certificateTokens, boolean signing) {
        if (Utils.isCollectionEmpty(certificateTokens)) {
            return;
        }

        final TokenStatus status = new TokenStatus();
        for (CertificateToken certificateToken : certificateTokens) {
            checkCertificateNotYetValid(certificateToken, status);
        }
        if (!status.isEmpty()) {
            if (signing) {
                status.setMessage("Error on signature creation.");
            } else {
                status.setMessage("Error on signature augmentation.");
            }
            certificateVerifier.getAlertOnNotYetValidCertificate().alert(status);
        }
    }

    private void checkCertificateNotYetValid(final CertificateToken certificateToken, final TokenStatus status) {
        if (certificateToken == null) {
            throw new IllegalInputException("Signing-certificate token was not found! Unable to verify its validity range. " +
                    "Provide signing-certificate or use method #setGenerateTBSWithoutCertificate(true) for signature creation without signing-certificate.");
        }

        if (isCertificateNotYetValid(certificateToken)) {
            final Date notBefore = certificateToken.getNotBefore();
            final Date notAfter = certificateToken.getNotAfter();
            final Date signingDate = signatureParameters.bLevel().getSigningDate();
            status.addRelatedTokenAndErrorMessage(certificateToken, String.format(
                    "The signing-certificate (notBefore : %s, notAfter : %s) is not yet valid at signing time %s!",
                    DSSUtils.formatDateToRFC(notBefore), DSSUtils.formatDateToRFC(notAfter), DSSUtils.formatDateToRFC(signingDate)));
        }
    }

    private boolean isCertificateNotYetValid(final CertificateToken certificateToken) {
        final Date notBefore = certificateToken.getNotBefore();
        final Date signingDate = signatureParameters.bLevel().getSigningDate();
        return signingDate.before(notBefore);
    }

    /**
     * This method verifies whether the given {@code CertificateToken} is not expired at the current time
     *
     * @param certificateToken {@link CertificateToken}
     */
    private void assertSigningCertificateIsNotExpired(final CertificateToken certificateToken) {
        assertCertificatesAreNotExpired(Collections.singletonList(certificateToken), true);
    }

    /**
     * This method verifies whether the given certificate tokens are yet valid at the current time
     *
     * @param certificateTokens a collection of {@link CertificateToken}s
     * @param signing defines whether the validation is performed on signing or augmentation process
     */
    private void assertCertificatesAreNotExpired(final Collection<CertificateToken> certificateTokens, boolean signing) {
        if (Utils.isCollectionEmpty(certificateTokens)) {
            return;
        }

        final TokenStatus status = new TokenStatus();
        for (CertificateToken certificateToken : certificateTokens) {
            checkCertificateExpired(certificateToken, status);
        }
        if (!status.isEmpty()) {
            if (signing) {
                status.setMessage("Error on signature creation.");
            } else {
                status.setMessage("Error on signature augmentation.");
            }
            certificateVerifier.getAlertOnExpiredCertificate().alert(status);
        }
    }

    private void checkCertificateExpired(final CertificateToken certificateToken, final TokenStatus status) {
        if (certificateToken == null) {
            throw new IllegalInputException("Signing-certificate token was not found! Unable to verify its validity range. " +
                    "Provide signing-certificate or use method #setGenerateTBSWithoutCertificate(true) for signature creation without signing-certificate.");
        }

        if (isCertificateExpired(certificateToken)) {
            final Date notBefore = certificateToken.getNotBefore();
            final Date notAfter = certificateToken.getNotAfter();
            final Date signingDate = signatureParameters.bLevel().getSigningDate();
            status.addRelatedTokenAndErrorMessage(certificateToken, String.format(
                    "The signing-certificate (notBefore : %s, notAfter : %s) is expired at signing time %s!",
                    DSSUtils.formatDateToRFC(notBefore), DSSUtils.formatDateToRFC(notAfter), DSSUtils.formatDateToRFC(signingDate)));
        }
    }

    private boolean isCertificateExpired(final CertificateToken certificateToken) {
        final Date notAfter = certificateToken.getNotAfter();
        final Date signingDate = signatureParameters.bLevel().getSigningDate();
        return signingDate.after(notAfter);
    }

    /**
     * This method verifies whether the given {@code CertificateToken} is not revoked nor suspended at the current time
     *
     * @param certificateToken {@link CertificateToken}
     */
    private void assertCertificatesAreNotRevoked(final CertificateToken certificateToken) {
        if (!signatureParameters.isCheckCertificateRevocation()) {
            return;
        }

        Date signingDate = signatureParameters.bLevel().getSigningDate();
        final SignatureValidationContext validationContext = new SignatureValidationContext(signingDate);
        validationContext.initialize(certificateVerifier);

        final List<CertificateToken> certificateChain = signatureParameters.getCertificateChain();
        if (Utils.isCollectionEmpty(certificateChain)) {
            throw new NullPointerException("Certificate chain shall be provided for a revocation check! " +
                    "Please use parameters.setCertificateChain(...) method to provide a certificate chain.");
        }
        validationContext.addCertificateTokenForVerification(certificateToken);
        for (CertificateToken certificate : certificateChain) {
            validationContext.addCertificateTokenForVerification(certificate);
        }
        validationContext.validate();

        validationContext.checkAllRequiredRevocationDataPresent();
        validationContext.checkCertificateNotRevoked(certificateToken);
    }

    /**
     * This method verifies whether the given {@code AdvancedSignature}s do not contain revoked certificates
     *
     * @param signatures a collection of {@link AdvancedSignature}s
     */
    private void assertCertificatesAreNotRevoked(final Collection<AdvancedSignature> signatures) {
        if (!signatureParameters.isCheckCertificateRevocation()) {
            return;
        }

        Date signingDate = signatureParameters.bLevel().getSigningDate();
        final SignatureValidationContext validationContext = new SignatureValidationContext(signingDate);
        validationContext.initialize(certificateVerifier);
        for (AdvancedSignature signature : signatures) {
            validationContext.addSignatureForVerification(signature);
        }
        validationContext.validate();

        validationContext.checkAllRequiredRevocationDataPresent();
        validationContext.checkAllSignatureCertificatesNotRevoked();
    }

    /**
     * Verifies whether extension of {@code signatures} to T-level is possible
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    public void assertExtendToTLevelPossible(List<AdvancedSignature> signatures) {
        assertTLevelIsHighest(signatures);
    }

    /**
     * Checks whether across {@code signatures} the T-level is highest and T-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertTLevelIsHighest(List<AdvancedSignature> signatures) {
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
     * @param signature {@link AdvancedSignature} to be verifies
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
    }

    /**
     * Checks whether across {@code signatures} the LT-level is highest and LT-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertLTLevelIsHighest(List<AdvancedSignature> signatures) {
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
     * @param signature {@link AdvancedSignature} to be verifies
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
    }

    /**
     * Checks whether across {@code signatures} the C-level is highest and C-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertCLevelIsHighest(List<AdvancedSignature> signatures) {
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
     * @param signature {@link AdvancedSignature} to be verifies
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
    }

    /**
     * Checks whether across {@code signatures} the X-level is highest and X-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertXLevelIsHighest(List<AdvancedSignature> signatures) {
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
     * @param signature {@link AdvancedSignature} to be verifies
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
    }

    /**
     * Checks whether across {@code signatures} the XL-level is highest and XL-level augmentation can be performed
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void assertXLLevelIsHighest(List<AdvancedSignature> signatures) {
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
     * @param signature {@link AdvancedSignature} to be verifies
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
     * Verifies cryptographical validity of the signatures
     *
     * @param signatures a collection of {@link AdvancedSignature}s
     */
    public void assertSignaturesValid(final Collection<AdvancedSignature> signatures) {
        final List<AdvancedSignature> signaturesToValidate = signatures.stream()
                .filter(s -> !isSignatureGeneratedWithoutCertificate(s)).collect(Collectors.toList());
        if (Utils.isCollectionEmpty(signaturesToValidate)) {
            return;
        }

        SignatureStatus status = new SignatureStatus();
        for (AdvancedSignature signature : signaturesToValidate) {
            final SignatureCryptographicVerification signatureCryptographicVerification = signature.getSignatureCryptographicVerification();
            if (!signatureCryptographicVerification.isSignatureIntact()) {
                final String errorMessage = signatureCryptographicVerification.getErrorMessage();
                status.addRelatedTokenAndErrorMessage(signature, "Cryptographic signature verification has failed"
                        + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
            }
        }
        if (!status.isEmpty()) {
            status.setMessage("Error on signature augmentation.");
            certificateVerifier.getAlertOnInvalidSignature().alert(status);
        }
    }

}
