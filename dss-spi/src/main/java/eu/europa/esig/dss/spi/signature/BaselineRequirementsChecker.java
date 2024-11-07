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
package eu.europa.esig.dss.spi.signature;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Checks conformance of a signature to the requested baseline format
 *
 * @param <AS> {@code DefaultAdvancedSignature}
 *
 */
public abstract class BaselineRequirementsChecker<AS extends DefaultAdvancedSignature> {

    private static final Logger LOG = LoggerFactory.getLogger(BaselineRequirementsChecker.class);

    /** The signature object */
    protected final AS signature;

    /** The offline copy of a CertificateVerifier */
    protected final CertificateVerifier offlineCertificateVerifier;

    /** Cached ValidationContext object to ensure validation is processed only once */
    private ValidationContext validationContext;

    /**
     * Constructor without {@code CertificateVerifier} (to be used for B-level validation only)
     *
     * @param signature {@link DefaultAdvancedSignature} to validate
     */
    protected BaselineRequirementsChecker(final AS signature) {
        this(signature, null);
    }

    /**
     * Default constructor
     *
     * @param signature {@link DefaultAdvancedSignature} to validate
     * @param offlineCertificateVerifier {@link CertificateVerifier} offline copy of a used CertificateVerifier
     */
    protected BaselineRequirementsChecker(final AS signature, final CertificateVerifier offlineCertificateVerifier) {
        this.signature = signature;
        this.offlineCertificateVerifier = offlineCertificateVerifier;
    }

    /**
     * Checks if the signature has a corresponding BASELINE-B profile
     *
     * @return TRUE if the signature has a BASELINE-B profile, FALSE otherwise
     */
    public abstract boolean hasBaselineBProfile();

    /**
     * Checks if the signature has a corresponding BASELINE-T profile
     *
     * @return TRUE if the signature has a BASELINE-T profile, FALSE otherwise
     */
    public abstract boolean hasBaselineTProfile();

    /**
     * Checks if the signature has a corresponding BASELINE-LT profile
     *
     * @return TRUE if the signature has a BASELINE-LT profile, FALSE otherwise
     */
    public abstract boolean hasBaselineLTProfile();

    /**
     * Checks if the signature has a corresponding BASELINE-LTA profile
     *
     * @return TRUE if the signature has a BASELINE-LTA profile, FALSE otherwise
     */
    public abstract boolean hasBaselineLTAProfile();

    /**
     * Checks if the signature has a corresponding *AdES-BES profile
     *
     * @return TRUE if the signature has a *AdES-BES profile, FALSE otherwise
     */
    public boolean hasExtendedBESProfile() {
        // not implemented by default
        return false;
    }

    /**
     * Checks if the signature has a corresponding *AdES-EPES profile
     *
     * @return TRUE if the signature has a *AdES-EPES profile, FALSE otherwise
     */
    public boolean hasExtendedEPESProfile() {
        // not implemented by default
        return false;
    }

    /**
     * Checks if the signature has a corresponding *AdES-T profile
     *
     * @return TRUE if the signature has a *AdES-T profile, FALSE otherwise
     */
    public boolean hasExtendedTProfile() {
        // not implemented by default
        return false;
    }

    /**
     * Checks if the signature has a corresponding *AdES-C profile
     *
     * @return TRUE if the signature has a *AdES-C profile, FALSE otherwise
     */
    public boolean hasExtendedCProfile() {
        // not implemented by default
        return false;
    }

    /**
     * Checks if the signature has a corresponding *AdES-X profile
     *
     * @return TRUE if the signature has a *AdES-X profile, FALSE otherwise
     */
    public boolean hasExtendedXProfile() {
        // not implemented by default
        return false;
    }

    /**
     * Checks if the signature has a corresponding *AdES-XL profile
     *
     * @return TRUE if the signature has a *AdES-XL profile, FALSE otherwise
     */
    public boolean hasExtendedXLProfile() {
        // not implemented by default
        return false;
    }

    /**
     * Checks if the signature has a corresponding *AdES-A profile
     *
     * @return TRUE if the signature has a *AdES-A profile, FALSE otherwise
     */
    public boolean hasExtendedAProfile() {
        // not implemented by default
        return false;
    }

    /**
     * Checks whether signature timestamps have been created before expiration of the signing-certificate
     * used to create the signature
     *
     * @return TRUE if the available signature-time-stamps have been created
     *         before expiration of the signing certificate, FALSE otherwise
     */
    protected boolean signatureTimestampsCreatedBeforeSignCertExpiration() {
        CertificateToken signingCertificate = signature.getSigningCertificateToken();
        if (signingCertificate != null && signingCertificate.getNotAfter() != null) {
            for (TimestampToken timestampToken : signature.getSignatureTimestamps()) {
                if (signingCertificate.getNotAfter().before(timestampToken.getGenerationTime())) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Checks the minimal requirement to satisfy T-profile for AdES signatures
     *
     * @return TRUE if the signature has a T-profile, FALSE otherwise
     */
    protected boolean minimalTRequirement() {
        // SignatureTimeStamp (Cardinality >= 1)
        if (Utils.isCollectionEmpty(signature.getSignatureTimestamps())) {
            LOG.trace("SignatureTimeStamp shall be present for BASELINE-T signature (cardinality >= 1)!");
            return false;
        }
        CertificateToken signingCertificate = signature.getSigningCertificateToken();
        if (signingCertificate != null) {
            for (TimestampToken timestampToken : signature.getSignatureTimestamps()) {
                if (!timestampToken.getCreationDate().before(signingCertificate.getNotAfter())) {
                    LOG.warn("SignatureTimeStamp shall be generated before the signing certificate expiration for BASELINE-T signature!");
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Checks the minimal requirement to satisfy LT-profile for AdES signatures
     *
     * @return TRUE if the signature has an LT-profile, FALSE otherwise
     */
    public boolean minimalLTRequirement() {
        Objects.requireNonNull(offlineCertificateVerifier, "offlineCertificateVerifier cannot be null for LT-level verification!");

        ListCertificateSource certificateSources = getCertificateSourcesExceptLastArchiveTimestamp();
        boolean certificateFound = certificateSources.getNumberOfCertificates() > 0;
        boolean allSelfSigned = certificateFound && certificateSources.isAllSelfSigned();

        boolean emptyCRLs = signature.getCompleteCRLSource().getAllRevocationBinaries().isEmpty();
        boolean emptyOCSPs = signature.getCompleteOCSPSource().getAllRevocationBinaries().isEmpty();
        boolean emptyRevocation = emptyCRLs && emptyOCSPs;

        boolean minimalLTRequirement = !allSelfSigned && !emptyRevocation;
        if (minimalLTRequirement) {
            // check presence of all revocation data
            return isAllRevocationDataPresent();
        }
        // Or one of the LT-/XL- profile properties are present (for self-signed cert chains only)
        if (allSelfSigned) {
            return containsLTLevelCertificates();
        }
        return minimalLTRequirement;
    }

    /**
     * This method verifies whether the signature contains some of the LT-/XL level attributes
     *
     * @return TRUE if the signature contains LT-/XL- level attributes, FALSE otherwise
     */
    protected boolean containsLTLevelCertificates() {
        // FALSE by default
        return false;
    }

    /**
     * Returns a list of certificate sources with an exception to the last archive timestamp if applicable
     *
     * @return {@link ListCertificateSource}
     */
    protected ListCertificateSource getCertificateSourcesExceptLastArchiveTimestamp() {
        ListCertificateSource certificateSource = new ListCertificateSource(signature.getCertificateSource());
        certificateSource.addAll(signature.getTimestampSource().getTimestampCertificateSourcesExceptLastArchiveTimestamp());
        certificateSource.addAll(signature.getCounterSignaturesCertificateSource());
        return certificateSource;
    }

    private boolean isAllRevocationDataPresent() {
        return getValidationContext().checkAllRequiredRevocationDataPresent();
    }

    /**
     * Returns a validated validation context
     *
     * @return {@link ValidationContext}
     */
    protected ValidationContext getValidationContext() {
        if (validationContext == null) {
            validationContext = new SignatureValidationContext();
            validationContext.initialize(offlineCertificateVerifier);

            validationContext.addDocumentCertificateSource(signature.getCompleteCertificateSource());
            validationContext.addDocumentCRLSource(signature.getCompleteCRLSource());
            validationContext.addDocumentOCSPSource(signature.getCompleteOCSPSource());

            addSignatureForVerification(validationContext, signature);

            validationContext.validate();
        }
        return validationContext;
    }

    private void addSignatureForVerification(ValidationContext validationContext, AdvancedSignature signature) {
        CertificateToken signingCertificate = signature.getSigningCertificateToken();
        if (signingCertificate != null) {
            validationContext.addCertificateTokenForVerification(signingCertificate);
        } else {
            CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
            List<CertificateValidity> certificateValidities = candidatesForSigningCertificate.getCertificateValidityList();
            if (Utils.isCollectionNotEmpty(certificateValidities)) {
                for (CertificateValidity certificateValidity : certificateValidities) {
                    if (certificateValidity.isValid() && certificateValidity.getCertificateToken() != null) {
                        validationContext.addCertificateTokenForVerification(certificateValidity.getCertificateToken());
                    }
                }
            }
        }
        for (TimestampToken timestampToken : signature.getTimestampSource().getAllTimestampsExceptLastArchiveTimestamp()) {
            validationContext.addTimestampTokenForVerification(timestampToken);
        }
    }

    /**
     * Checks the minimal requirement to satisfy LTA-profile for AdES signatures
     *
     * @return TRUE if the signature has an LTA-profile, FALSE otherwise
     */
    public boolean minimalLTARequirement() {
        if (Utils.isCollectionEmpty(signature.getArchiveTimestamps())) {
            LOG.trace("ArchiveTimeStamp shall be present for BASELINE-LTA signature (cardinality >= 1)!");
            return false;
        }
        return true;
    }

    /**
     * Checks if the given collection of {@code CertificateToken}s contains the signing certificate for the signature
     *
     * @param certificateTokens a collection of {@link CertificateToken}s
     * @return TRUE if the given collection of certificate contains teh signing certificate, FALSE otherwise
     */
    protected boolean containsSigningCertificate(Collection<CertificateToken> certificateTokens) {
        CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
        CertificateValidity certificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
        if (certificateValidity != null && certificateValidity.getCertificateToken() != null) {
            CertificateToken signingCertificate = certificateValidity.getCertificateToken();
            for (CertificateToken certificate : certificateTokens) {
                if (certificate.equals(signingCertificate)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the signature contains a SignaturePolicyIdentifier
     * containing a hash used to digest the signature policy
     *
     * @return TRUE if the SignaturePolicyIdentifier hash is present, FALSE otherwise
     */
    protected boolean isSignaturePolicyIdentifierHashPresent() {
        SignaturePolicy signaturePolicyIdentifier = signature.getSignaturePolicy();
        if (signaturePolicyIdentifier != null) {
            Digest digest = signaturePolicyIdentifier.getDigest();
            return digest != null && digest.getAlgorithm() != null;
        }
        return false;
    }

}
