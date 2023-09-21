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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESBaselineRequirementsChecker;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureValidationContext;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import org.bouncycastle.cms.CMSTypedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Performs checks according to EN 319 142-1 v1.1.1
 * "6.3 PAdES baseline signatures"
 *
 */
public class PAdESBaselineRequirementsChecker extends CAdESBaselineRequirementsChecker {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESBaselineRequirementsChecker.class);

    /** Mandatory value for content-type attribute for PAdES-BASELINE-B profile */
    private static final String CONTENT_TYPE_ID_DATA = "1.2.840.113549.1.7.1";

    /**
     * Default constructor
     *
     * @param signature                  {@link PAdESSignature}
     * @param offlineCertificateVerifier {@link CertificateVerifier}
     */
    public PAdESBaselineRequirementsChecker(PAdESSignature signature, CertificateVerifier offlineCertificateVerifier) {
        super(signature, offlineCertificateVerifier);
    }

    @Override
    protected SignatureForm getBaselineSignatureForm() {
        return SignatureForm.PAdES;
    }

    @Override
    public boolean hasBaselineBProfile() {
        if (!cmsBaselineBRequirements()) {
            return false;
        }
        PAdESSignature padesSignature = (PAdESSignature) signature;
        PdfSignatureDictionary pdfSignatureDictionary = padesSignature.getPdfSignatureDictionary();
        // SPO: entry with the key M in the Signature Dictionary (Cardinality == 1)
        if (pdfSignatureDictionary.getSigningDate() == null) {
            LOG.warn("Entry with the key M in the Signature Dictionary shall be present " +
                    "for PAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // SPO: entry with the key Contents in the Signature Dictionary (Cardinality == 1)
        if (Utils.isArrayEmpty(pdfSignatureDictionary.getContents())) {
            LOG.warn("Entry with the key Contents in the Signature Dictionary shall be present " +
                    "for PAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // SPO: entry with the key Filter in the Signature Dictionary (Cardinality == 1)
        if (Utils.isStringEmpty(pdfSignatureDictionary.getFilter())) {
            LOG.warn("Entry with the key Filter in the Signature Dictionary shall be present " +
                    "for PAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // SPO: entry with the key ByteRange in the Signature Dictionary (Cardinality == 1)
        if (pdfSignatureDictionary.getByteRange() == null) {
            LOG.warn("Entry with the key ByteRange in the Signature Dictionary shall be present " +
                    "for PAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // SPO: entry with the key SubFilter in the Signature Dictionary (Cardinality == 1)
        if (Utils.isStringEmpty(pdfSignatureDictionary.getSubFilter())) {
            LOG.warn("Entry with the key SubFilter in the Signature Dictionary shall be present " +
                    "for PAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // SPO: entry with the key Cert in the Signature Dictionary (Cardinality == 0) (not supported)
        // Additional requirement (c)
        if (!CONTENT_TYPE_ID_DATA.equals(padesSignature.getContentType())) {
            LOG.warn("content-type attribute shall have value id-data for PAdES-BASELINE-B signature! (requirement (c))");
            return false;
        }
        // Additional requirement (d)
        if (Utils.isStringNotEmpty(pdfSignatureDictionary.getReason()) &&
                Utils.isCollectionNotEmpty(padesSignature.getCommitmentTypeIndications())) {
            LOG.warn("commitment-type-indication attribute shall not be incorporated in the CMS signature " +
                    "when entry with a key Reason is used for PAdES-BASELINE-B signature! (requirement (d))");
            return false;
        }
        // Additional requirement (l)
        if (!PAdESConstants.SIGNATURE_DEFAULT_SUBFILTER.equals(pdfSignatureDictionary.getSubFilter())) {
            LOG.warn("Entry with a key SubFilter shall contain a value ETSI.CAdES.detached " +
                    "for PAdES-BASELINE-B signature! (requirement (l))");
            return false;
        }
        // Additional requirement (m)
        if ((Utils.isCollectionNotEmpty(padesSignature.getCommitmentTypeIndications()) ||
                padesSignature.getSignaturePolicy() != null) && Utils.isStringNotEmpty(pdfSignatureDictionary.getReason())) {
            LOG.warn("Entry with a key Reason shall not be used when commitment-type-attribute or " +
                    "signature-policy-identifier is present in the CMS signature for PAdES-BASELINE-B signature! (requirement (m))");
            return false;
        }
        if (!padesSignature.getCmsSignedData().isDetachedSignature()) {
            LOG.warn("No data shall be encapsulated in the PKCS#7 SignedData field for PAdES-BASELINE-B signature!");
            return false;
        }
        return true;
    }

    @Override
    protected boolean cmsBaselineBRequirements() {
        CMSForPAdESBaselineRequirementsChecker cmsRequirementsChecker = new CMSForPAdESBaselineRequirementsChecker(signature);
        return cmsRequirementsChecker.isValidForPAdESBaselineBProfile();
    }

    @Override
    public boolean hasBaselineTProfile() {
        // signature-time-stamp or document-time-stamp (Cardinality >= 1)
        if (Utils.isCollectionEmpty(signature.getSignatureTimestamps()) &&
                Utils.isCollectionEmpty(signature.getDocumentTimestamps())) {
            LOG.trace("SignatureTimeStamp shall be present for BASELINE-T signature (cardinality >= 1)!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTProfile() {
        return hasLTProfile();
    }

    /**
     * Verifies a presence of LT-profile for a PDF signature
     *
     * @return TRUE if the LT-profile is present, FALSE otherwise
     */
    protected boolean hasLTProfile() {
        if (!minimalLTRequirement()) {
            return false;
        }
        PAdESSignature padesSignature = (PAdESSignature) signature;
        boolean allSelfSigned = padesSignature.getCertificateSource().isAllSelfSigned();
        // SPO: DSS
        if (!allSelfSigned && padesSignature.getDssDictionary() == null) {
            LOG.warn("DSS dictionary shall be present for PAdES-BASELINE-LT signature! (cardinality >= 1)");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTAProfile() {
        // Additional requirement (y)
        boolean ltaTimestampFound = false;
        for (TimestampToken timestampToken : signature.getDocumentTimestamps()) {
            if (isBaselineLTATimestamp(timestampToken)) {
                ltaTimestampFound = true;
                break;
            }
        }
        if (!ltaTimestampFound) {
            LOG.debug("document-time-stamp covering LT-level and containing a key SubFilter with value ETSI.RFC3161 " +
                    "shall be present for PAdES-BASELINE-LTA signature! (cardinality >= 1, requirement (y))");
            return false;
        }
        return true;
    }

    private boolean isBaselineLTATimestamp(TimestampToken timestampToken) {
        return containsRFC3161SubFilter(timestampToken) && coversLTLevelData(timestampToken);
    }

    private boolean coversLTLevelData(TimestampToken timestampToken) {
        if (ArchiveTimestampType.PAdES.equals(timestampToken.getArchiveTimestampType())) {
            ValidationContext validationContext = getValidationContext();
            ValidationData signatureValidationData = validationContext.getValidationData(signature);
            Set<CertificateToken> certificateTokens = signatureValidationData.getCertificateTokens();
            Set<CRLToken> crlTokens = signatureValidationData.getCrlTokens();
            Set<OCSPToken> ocspTokens = signatureValidationData.getOcspTokens();
            List<TimestampToken> allTimestamps = signature.getAllTimestamps();

            if (Utils.isCollectionEmpty(crlTokens) && Utils.isCollectionEmpty(ocspTokens)) {
                return coversDSSCertificateTokens(timestampToken, certificateTokens);
            } else {
                return coversRevocationTokens(timestampToken, crlTokens, ocspTokens) &&
                        (coversTimestampTokens(timestampToken, allTimestamps) || coversOwnRevocationData(timestampToken));
            }
        }
        return false;
    }

    private boolean coversDSSCertificateTokens(TimestampToken timestampToken, Collection<CertificateToken> certificateTokens) {
        List<CertificateToken> dssCertificates = new ArrayList<>();
        dssCertificates.addAll(signature.getCertificateSource().getDSSDictionaryCertValues());
        dssCertificates.addAll(signature.getCertificateSource().getVRIDictionaryCertValues());
        if (Utils.isCollectionNotEmpty(dssCertificates)) {
            for (CertificateToken certificateToken : certificateTokens) {
                if (dssCertificates.contains(certificateToken) && coversToken(timestampToken, certificateToken)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * This method verifies whether all the revocation data is covered by the given timestamp
     * to fulfil the minimum requirement for LT-level.
     *
     * NOTE: This method checks coverage of the available revocation data,
     * and the actual LT-level shall be determined in prior using {@code hasBaselineLTProfile()} method!
     *
     * @param timestampToken {@link TimestampToken} to verify
     * @param crlTokens a collection of {@link CRLToken}s used for signature validation
     * @param ocspTokens a collection of {@link OCSPToken}s used for signature validation
     * @return TRUE if the timestamp covers all the given revocation data to fulfil the minimum LT-level requirement,
     *         FALSE otherwise
     */
    private boolean coversRevocationTokens(TimestampToken timestampToken,
                                           Collection<CRLToken> crlTokens, Collection<OCSPToken> ocspTokens) {
        Map<String, Collection<RevocationToken<?>>> revocationsByCertificate = getRevocationsByCertificate(crlTokens, ocspTokens);
        for (Collection<RevocationToken<?>> revocationTokens : revocationsByCertificate.values()) {
            boolean revocationForCertificateIsCovered = false;
            for (RevocationToken<?> revocationToken : revocationTokens) {
                if (coversToken(timestampToken, revocationToken)) {
                    revocationForCertificateIsCovered = true;
                    break;
                }
            }
            if (!revocationForCertificateIsCovered) {
                return false;
            }
        }
        return true;
    }

    private boolean coversTimestampTokens(TimestampToken timestampToken, Collection<TimestampToken> signatureTimestampTokens) {
        List<TimestampedReference> timestampedReferences = timestampToken.getTimestampedReferences();
        if (Utils.isCollectionNotEmpty(timestampedReferences)) {
            for (TimestampToken sigTst : signatureTimestampTokens) {
                if (timestampedReferences.stream().anyMatch(r -> sigTst.getDSSIdAsString().equals(r.getObjectId()))) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean coversOwnRevocationData(TimestampToken timestampToken) {
        SignatureValidationContext validationContext = new SignatureValidationContext();
        validationContext.initialize(offlineCertificateVerifier);

        validationContext.addDocumentCertificateSource(signature.getCompleteCertificateSource());
        validationContext.addDocumentCRLSource(signature.getCompleteCRLSource());
        validationContext.addDocumentOCSPSource(signature.getCompleteOCSPSource());

        validationContext.addTimestampTokenForVerification(timestampToken);
        validationContext.validate();

        ValidationData validationData = validationContext.getValidationData(timestampToken);
        Set<String> revocationTokenIdentifiers = new HashSet<>();
        revocationTokenIdentifiers.addAll(validationData.getCrlTokens().stream().map(CRLToken::getDSSIdAsString).collect(Collectors.toSet()));
        revocationTokenIdentifiers.addAll(validationData.getOcspTokens().stream().map(OCSPToken::getDSSIdAsString).collect(Collectors.toSet()));

        if (Utils.isCollectionEmpty(revocationTokenIdentifiers)) {
            return validationContext.checkAllRequiredRevocationDataPresent();
        }

        List<TimestampedReference> timestampedReferences = timestampToken.getTimestampedReferences();
        return timestampedReferences.stream().anyMatch(r -> revocationTokenIdentifiers.contains(r.getObjectId()));
    }

    /**
     * This method returns collections of revocation data filtered by a certificate.
     * This allows to ensure a minimum requirement of revocation data for LT-level
     * to be covered by an archival timestamp.
     *
     * @param crlTokens collection of {@link CRLToken}s
     * @param ocspTokens collection of {@link OCSPToken}s
     * @return a map between related certificate id and corresponding collection of related revocation data
     */
    private Map<String, Collection<RevocationToken<?>>> getRevocationsByCertificate(Collection<CRLToken> crlTokens,
                                                                                Collection<OCSPToken> ocspTokens) {
        Map<String, Collection<RevocationToken<?>>> result = new HashMap<>();
        enrichRevocationDataMap(result, crlTokens);
        enrichRevocationDataMap(result, ocspTokens);
        return result;
    }

    private <R extends RevocationToken<?>> void enrichRevocationDataMap(
            Map<String, Collection<RevocationToken<?>>> revocationDataMap, Collection<R> revocationData) {
        for (RevocationToken<?> revocationToken : revocationData) {
            String relatedCertificateId = revocationToken.getRelatedCertificateId();
            Collection<RevocationToken<?>> relatedRevocationData = revocationDataMap.get(relatedCertificateId);
            if (Utils.isCollectionEmpty(relatedRevocationData)) {
                relatedRevocationData = new HashSet<>();
                revocationDataMap.put(relatedCertificateId, relatedRevocationData);
            }
            relatedRevocationData.add(revocationToken);
        }
    }

    private boolean coversToken(TimestampToken timestampToken, Token token) {
        List<TimestampedReference> timestampedReferences = timestampToken.getTimestampedReferences();
        for (TimestampedReference timestampedReference : timestampedReferences) {
            if (token.getDSSIdAsString().equals(timestampedReference.getObjectId())) {
                return true;
            }
        }
        return false;
    }

    private boolean containsRFC3161SubFilter(TimestampToken timestampToken) {
        if (timestampToken instanceof PdfTimestampToken) {
            PdfDocTimestampRevision pdfRevision = ((PdfTimestampToken) timestampToken).getPdfRevision();
            if (pdfRevision != null) {
                PdfSignatureDictionary pdfSigDictInfo = pdfRevision.getPdfSigDictInfo();
                return pdfSigDictInfo != null && PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(pdfSigDictInfo.getSubFilter());
            }
        }
        return false;
    }

    /**
     * Checks if the signature has PKCS#7 profile (according to ISO 32000-1)
     *
     * @return TRUE if the signature has a PKCS#7 profile, FALSE otherwise
     */
    public boolean hasPKCS7Profile() {
        PAdESSignature padesSignature = (PAdESSignature) signature;
        PdfSignatureDictionary pdfSignatureDictionary = padesSignature.getPdfSignatureDictionary();
        // SubFilter shall take one of the following values: (adbe.pkcs7.detached, adbe.pkcs7.sha1)
        if (!PAdESConstants.SIGNATURE_PKCS7_SUBFILTER.equals(pdfSignatureDictionary.getSubFilter()) &&
                !PAdESConstants.SIGNATURE_PKCS7_SHA1_SUBFILTER.equals(pdfSignatureDictionary.getSubFilter())) {
            LOG.debug("Entry with a key SubFilter shall have a value adbe.pkcs7.detached or adbe.pkcs7.sha1 " +
                    "for PKCS#7 signature!");
            return false;
        }
        // At minimum the CMS object shall include the signer’s X.509 signing certificate.
        if (!containsSigningCertificate(padesSignature.getCertificateSource().getCertificates())) {
            LOG.warn("PKCS#7 signature shall include signing certificate!");
            return false;
        }
        // SubFilter adbe.pkcs7.detached
        if (PAdESConstants.SIGNATURE_PKCS7_SUBFILTER.equals(pdfSignatureDictionary.getSubFilter())) {
            // The original signed message digest over the document’s byte range shall be
            // incorporated as the normal CMS SignedData field.
            if (Utils.isArrayEmpty(padesSignature.getMessageDigestValue())) {
                LOG.warn("PKCS#7 signature shall include message digest!");
                return false;
            }
            // No data shall be encapsulated in the CMS SignedData field.
            if (!padesSignature.getCmsSignedData().isDetachedSignature()) {
                LOG.warn("No data shall be encapsulated in the CMS SignedData field for PKCS#7 signature!");
                return false;
            }
        }
        // SubFilter adbe.pkcs7.sha1
        if (PAdESConstants.SIGNATURE_PKCS7_SHA1_SUBFILTER.equals(pdfSignatureDictionary.getSubFilter())) {
            CMSTypedData signedContent = padesSignature.getCmsSignedData().getSignedContent();
            if (signedContent == null) {
                LOG.warn("ContentInfo of type Data shall be encapsulated in the CMS SignedData field for " +
                        "PKCS#7 signature with SHA-1 SubFilter!");
                return false;
            }
            byte[] signedContentBytes = CMSUtils.getSignedContent(signedContent);
            if (!DSSUtils.isSHA1Digest(Utils.toHex(signedContentBytes))) {
                LOG.warn("The SHA-1 digest of the document’s byte range shall be encapsulated in the CMS " +
                        "SignedData field with ContentInfo of type Data for PKCS#7 signature with SHA-1 SubFilter!");
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if the signature has PKCS#7-T profile
     *
     * @return TRUE if the signature has a PKCS#7-T profile, FALSE otherwise
     */
    public boolean hasPKCS7TProfile() {
        return hasBaselineTProfile();
    }

    /**
     * Checks if the signature has PKCS#7-LT profile
     *
     * @return TRUE if the signature has a PKCS#7-LT profile, FALSE otherwise
     */
    public boolean hasPKCS7LTProfile() {
        return hasLTProfile();
    }

    /**
     * Checks if the signature has PKCS#7-LTA profile
     *
     * @return TRUE if the signature has a PKCS#7-LTA profile, FALSE otherwise
     */
    public boolean hasPKCS7LTAProfile() {
        boolean ltaTimestampFound = false;
        for (TimestampToken timestampToken : signature.getDocumentTimestamps()) {
            if (coversLTLevelData(timestampToken)) {
                ltaTimestampFound = true;
                break;
            }
        }
        if (!ltaTimestampFound) {
            LOG.debug("document-time-stamp covering LT-level shall be present for PKCS#7-LTA signature!");
            return false;
        }
        return true;
    }

}
