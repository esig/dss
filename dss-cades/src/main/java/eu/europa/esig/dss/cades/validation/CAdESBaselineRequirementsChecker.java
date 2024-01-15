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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.BaselineRequirementsChecker;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

/**
 * Performs checks according to EN 319 122-1 v1.1.1
 * "6.3 Requirements on components and services"
 *
 */
public class CAdESBaselineRequirementsChecker extends BaselineRequirementsChecker<CAdESSignature> {

    private static final Logger LOG = LoggerFactory.getLogger(CAdESBaselineRequirementsChecker.class);

    /**
     * Constructor is used to verify conformance of signature to Baseline-B level
     *
     * @param signature {@link CAdESSignature}
     */
    protected CAdESBaselineRequirementsChecker(final CAdESSignature signature) {
        this(signature, null);
    }

    /**
     * Default constructor
     *
     * @param signature {@link CAdESSignature}
     * @param offlineCertificateVerifier {@link CertificateVerifier}
     */
    public CAdESBaselineRequirementsChecker(final CAdESSignature signature,
                                            final CertificateVerifier offlineCertificateVerifier) {
        super(signature, offlineCertificateVerifier);
    }

    /**
     * Returns the signature form corresponding to the signature
     *
     * @return {@link SignatureForm}
     */
    protected SignatureForm getBaselineSignatureForm() {
        return SignatureForm.CAdES;
    }

    /**
     * Checks if BASELINE-B requirements satisfy for a CMS signature
     *
     * @return TRUE if the CMS signature meet the BASELINE-B requirements, FALSE otherwise
     */
    protected boolean cmsBaselineBRequirements() {
        CMSSignedData cmsSignedData = signature.getCmsSignedData();
        SignerInformation signerInformation = signature.getSignerInformation();
        SignatureForm signatureForm = getBaselineSignatureForm();
        // SignedData.certificates (Cardinality == 1)
        if (Utils.isCollectionEmpty(cmsSignedData.getCertificates().getMatches(null))) {
            LOG.warn("SignedData.certificates shall be present for {}-BASELINE-B signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // content-type (Cardinality == 1)
        if (!isContentTypeValid(signerInformation)) {
            LOG.warn("content-type attribute shall be present for {}-BASELINE-B signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // message-digest (Cardinality == 1)
        if (!isMessageDigestPresent(signerInformation)) {
            LOG.warn("message-digest attribute shall be present for {}-BASELINE-B signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // signing-certificate/signing-certificate-v2 (Cardinality == 1)
        if (!isOneSigningCertificatePresent(signerInformation)) {
            LOG.warn("signing-certificate(-v2) attribute shall be present for {}-BASELINE-B signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // signing-time (Cardinality == 1)
        Attribute[] signingTimeAttrs = CMSUtils.getSignedAttributes(signerInformation,
                PKCSObjectIdentifiers.pkcs_9_at_signingTime);
        boolean signingTimePresent = Utils.arraySize(signingTimeAttrs) == 1;
        boolean cades = SignatureForm.CAdES.equals(signatureForm);
        if (signingTimePresent != cades) {
            if (cades) {
                LOG.warn("signing-time attribute shall be present for {}-BASELINE-B signature (cardinality == 1})!", signatureForm);
            } else {
                LOG.warn("signing-time attribute shall not be present for {}-BASELINE-B signature (cardinality == 0})!", signatureForm);
            }
            return false;
        }
        // Additional requirement (a)
        if (!containsSigningCertificate(signature.getCertificateSource().getSignedDataCertificates())) {
            LOG.warn("Signing certificate shall be present in SignedData.certificates " +
                    "for {}-BASELINE-B signature (requirement (a))!", signatureForm);
            return false;
        }
        // Additional requirement (f)
        if (signature.getContentType() != null && !PKCSObjectIdentifiers.data.getId().equals(signature.getContentType())) {
            LOG.warn("The content-type attribute shall have value id-data for {}-BASELINE-B signature " +
                    "(requirement (f))!", signatureForm);
            return false;
        }
        // Additional requirement (h) and (i)
        if (!isSigningCertificateAttributeValid(signerInformation)) {
            LOG.warn("signing-certificate attribute shall be used for SHA1 hash algorithm " +
                    "and signing-certificate-v2 for other hash algorithms for {}-BASELINE-B signature " +
                    "(requirements (h) and (i) 319 122-1)!", signatureForm);
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineBProfile() {
        if (!cmsBaselineBRequirements()) {
            return false;
        }
        // Additional requirement (k)
        SignaturePolicyStore signaturePolicyStore = signature.getSignaturePolicyStore();
        if (signaturePolicyStore != null && !isSignaturePolicyIdentifierHashPresent()) {
            LOG.warn("signature-policy-store shall not be present for CAdES-BASELINE-B signature with not defined " +
                    "signature-policy-identifier/sigPolicyHash (requirement (k))!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineTProfile() {
        if (!minimalTRequirement()) {
            return false;
        }
        // Additional requirement (m)
        if (!signatureTimestampsCreatedBeforeSignCertExpiration()) {
            LOG.warn("signature-time-stamp shall be created before expiration of the signing-certificate " +
                    "for CAdES-BASELINE-T signature (requirement (m))!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTProfile() {
        if (!minimalLTRequirement()) {
            return false;
        }
        SignerInformation signerInformation = signature.getSignerInformation();
        // certificate-values (Cardinality == 0)
        if (Utils.isArrayNotEmpty(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certValues))) {
            LOG.warn("certificate-values attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // complete-certificate-references (Cardinality == 0)
        if (Utils.isArrayNotEmpty(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certificateRefs))) {
            LOG.warn("complete-certificate-references attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // revocation-values (Cardinality == 0)
        if (Utils.isArrayNotEmpty(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_revocationValues))) {
            LOG.warn("revocation-values attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // complete-revocation-references (Cardinality == 0)
        if (Utils.isArrayNotEmpty(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_revocationRefs))) {
            LOG.warn("complete-revocation-references attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // time-stamped-certs-crls-references (Cardinality == 0)
        if (Utils.isArrayNotEmpty(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp))) {
            LOG.warn("time-stamped-certs-crls-references attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTAProfile() {
        List<TimestampToken> timestampTokens = new ArrayList<>();
        timestampTokens.addAll(signature.getArchiveTimestamps());
        timestampTokens.addAll(signature.getDetachedTimestamps());
        if (Utils.isCollectionEmpty(timestampTokens)) {
            LOG.trace("ArchiveTimeStamp shall be present for CAdES-BASELINE-LTA signature (cardinality >= 1)!");
            return false;
        }
        // archive-time-stamp-v3 / detached timestamps (Cardinality >= 1)
        boolean validArcTstFound = false;
        for (TimestampToken timestampToken : timestampTokens) {
            if (ArchiveTimestampType.CAdES_V3.equals(timestampToken.getArchiveTimestampType()) ||
                    timestampToken.getTimeStampType().isContainerTimestamp()) {
                validArcTstFound = true;
                break;
            }
        }
        if (!validArcTstFound) {
            LOG.warn("archive-time-stamp-v3 attribute shall be present " +
                    "for CAdES-BASELINE-LTA signature (cardinality == 1)!");
            return false;
        }
        return true;
    }

    /**
     * Checks if the signature has a corresponding CAdES-BES profile
     *
     * @return TRUE if the signature has a CAdES-BES profile, FALSE otherwise
     */
    public boolean hasExtendedBESProfile() {
        SignerInformation signerInformation = signature.getSignerInformation();
        SignatureForm signatureForm = getBaselineSignatureForm();
        // content-type (Cardinality == 1)
        if (!isContentTypeValid(signerInformation)) {
            LOG.warn("content-type attribute shall be present for {}-BES signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // message-digest (Cardinality == 1)
        if (!isMessageDigestPresent(signerInformation)) {
            LOG.warn("message-digest attribute shall be present for {}-BES signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // signing-certificate/signing-certificate-v2 (Cardinality == 1)
        if (!isOneSigningCertificatePresent(signerInformation)) {
            LOG.warn("signing-certificate(-v2) attribute shall be present for {}-BES signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // signing-time (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_signingTime)) > 1) {
            LOG.warn("signing-time attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // commitment-time-indication (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_commitmentType)) > 1) {
            LOG.warn("commitment-time-indication attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // content-hints (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_contentHint)) > 1) {
            LOG.warn("content-hints attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // mime-type (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, OID.id_aa_ets_mimeType)) > 1) {
            LOG.warn("mime-type attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // signer-location (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_signerLocation)) > 1) {
            LOG.warn("signer-location attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // signature-policy-identifier (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_sigPolicyId)) > 1) {
            LOG.warn("signature-policy-identifier attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // signature-policy-identifier (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_sigPolicyId)) > 1) {
            LOG.warn("signature-policy-identifier attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // signature-policy-store (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, OID.id_aa_ets_sigPolicyStore)) > 1) {
            LOG.warn("signature-policy-store attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // content-reference (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_contentReference)) > 1) {
            LOG.warn("content-reference attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // content-identifier (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_contentIdentifier)) > 1) {
            LOG.warn("content-identifier attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // complete-certificate-references (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certificateRefs)) > 1) {
            LOG.warn("complete-certificate-references attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // complete-revocation-references (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_revocationRefs)) > 1) {
            LOG.warn("complete-revocation-references attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // attribute-certificate-references (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, OID.attributeCertificateRefsOid)) > 1) {
            LOG.warn("attribute-certificate-references attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // attribute-revocation-references (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, OID.attributeRevocationRefsOid)) > 1) {
            LOG.warn("attribute-revocation-references attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // certificate-values (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certValues)) > 1) {
            LOG.warn("certificate-values attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // revocation-values (Cardinality == 0 or 1)
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_revocationValues)) > 1) {
            LOG.warn("revocation-values attribute shall not be present multiple times for {}-BES signature (cardinality == 0 or 1)!", signatureForm);
            return false;
        }
        // Additional requirement (h) and (i)
        if (!isSigningCertificateAttributeValid(signerInformation)) {
            LOG.warn("signing-certificate attribute shall be used for SHA1 hash algorithm " +
                    "and signing-certificate-v2 for other hash algorithms for {}-BES signature " +
                    "(requirements (a) and (b) 319 122-2)!", signatureForm);
            return false;
        }
        return true;
    }

    /**
     * Checks if the signature has a corresponding CAdES-EPES profile
     *
     * @return TRUE if the signature has a CAdES-EPES profile, FALSE otherwise
     */
    public boolean hasExtendedEPESProfile() {
        SignerInformation signerInformation = signature.getSignerInformation();
        SignatureForm signatureForm = getBaselineSignatureForm();
        // signature-policy-identifier (Cardinality == 1)
        Attribute[] sigPolicyIdAttrs = CMSUtils.getSignedAttributes(signerInformation,
                PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
        if (Utils.arraySize(sigPolicyIdAttrs) == 0) {
            LOG.debug("signature-policy-identifier attribute shall be present for {}-EPES signature " +
                    "(cardinality == 1)!", signatureForm);
            return false;
        }
        SignaturePolicyStore signaturePolicyStore = signature.getSignaturePolicyStore();
        if (signaturePolicyStore != null && !isSignaturePolicyIdentifierHashPresent()) {
            LOG.debug("signature-policy-store may be present for {}-EPES signature only if signature-policy-identifier " +
                    "is present and it contains sigPolicyHash element (requirement (c))!", signatureForm);
            return false;
        }
        return true;
    }

    /**
     * Checks if the signature has a corresponding CAdES-T profile
     *
     * @return TRUE if the signature has a CAdES-T profile, FALSE otherwise
     */
    public boolean hasExtendedTProfile() {
        if (!minimalTRequirement()) {
            return false;
        }
        // Additional requirement (f)
        if (!signatureTimestampsCreatedBeforeSignCertExpiration()) {
            LOG.warn("signature-time-stamp shall be created before expiration of the signing-certificate " +
                    "for CAdES-T signature (requirement (f))!");
            return false;
        }
        return true;
    }

    /**
     * Checks if the signature has a corresponding CAdES-C profile
     *
     * @return TRUE if the signature has a CAdES-C profile, FALSE otherwise
     */
    public boolean hasExtendedCProfile() {
        SignerInformation signerInformation = signature.getSignerInformation();
        // complete-certificate-references
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certificateRefs)) != 1) {
            LOG.debug("complete-certificate-references attribute shall be present for CAdES-C signature (cardinality == 1)!");
            return false;
        }
        // complete-revocation-references
        ListCertificateSource certificateSources = getCertificateSourcesExceptLastArchiveTimestamp();
        boolean certificateFound = certificateSources.getNumberOfCertificates() > 0;
        boolean allSelfSigned = certificateFound && certificateSources.isAllSelfSigned();
        Attribute[] revocationRefAttrs = CMSUtils.getUnsignedAttributes(signerInformation, PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
        if (Utils.arraySize(revocationRefAttrs) > 1) {
            LOG.debug("complete-revocation-references attribute shall be present only once for CAdES-C signature (cardinality == 1)!");
            return false;

        } else if (!allSelfSigned && Utils.arraySize(revocationRefAttrs) != 1) {
            LOG.debug("complete-revocation-references attribute shall be present for CAdES-C signature (cardinality == 1)!");
            return false;
        }
        return true;
    }

    /**
     * Checks if the signature has a corresponding CAdES-X profile
     *
     * @return TRUE if the signature has a CAdES-X profile, FALSE otherwise
     */
    public boolean hasExtendedXProfile() {
        SignerInformation signerInformation = signature.getSignerInformation();
        if (Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, id_aa_ets_certCRLTimestamp)) +
                Utils.arraySize(CMSUtils.getUnsignedAttributes(signerInformation, id_aa_ets_escTimeStamp)) != 1) {
            LOG.debug("complete-revocation-references attribute shall be present for CAdES-C signature (cardinality == 1)!");
            return false;
        }
        return true;
    }

    /**
     * Checks if the signature has a corresponding CAdES-XL profile
     *
     * @return TRUE if the signature has a CAdES-XL profile, FALSE otherwise
     */
    public boolean hasExtendedXLProfile() {
        return minimalLTRequirement();
    }

    /**
     * Checks if the signature has a corresponding CAdES-A profile
     *
     * @return TRUE if the signature has a CAdES-A profile, FALSE otherwise
     */
    public boolean hasExtendedAProfile() {
        List<TimestampToken> timestampTokens = new ArrayList<>();
        timestampTokens.addAll(signature.getArchiveTimestamps());
        timestampTokens.addAll(signature.getDetachedTimestamps());
        if (Utils.isCollectionEmpty(timestampTokens)) {
            LOG.trace("ArchiveTimeStamp shall be present for CAdES-A signature (cardinality >= 1)!");
            return false;
        }
        return true;
    }

    private boolean isContentTypeValid(SignerInformation signerInformation) {
        Attribute[] contentTypeAttrs = CMSUtils.getSignedAttributes(signerInformation,
                PKCSObjectIdentifiers.pkcs_9_at_contentType);
        int numberOfOccurrences = Utils.arraySize(contentTypeAttrs);
        if (signature.isCounterSignature() && numberOfOccurrences == 0) {
            return true;
        }
        return numberOfOccurrences == 1;
    }

    private boolean isMessageDigestPresent(SignerInformation signerInformation) {
        Attribute[] messageDigestAttrs = CMSUtils.getSignedAttributes(signerInformation,
                PKCSObjectIdentifiers.pkcs_9_at_messageDigest);
        return Utils.arraySize(messageDigestAttrs) == 1;
    }

    private boolean isOneSigningCertificatePresent(SignerInformation signerInformation) {
        Attribute[] signingCertAttrs = CMSUtils.getSignedAttributes(signerInformation, id_aa_signingCertificate);
        Attribute[] signingCertV2Attrs = CMSUtils.getSignedAttributes(signerInformation, id_aa_signingCertificateV2);
        return Utils.arraySize(signingCertAttrs) + Utils.arraySize(signingCertV2Attrs) == 1;
    }

    private boolean isSigningCertificateAttributeValid(SignerInformation signerInformation) {
        List<CertificateRef> certificateRefs = signature.getCertificateSource().getSigningCertificateRefs();
        if (Utils.isCollectionNotEmpty(certificateRefs)) {
            CertificateRef signingCertificateRef = certificateRefs.iterator().next(); // only one shall be used
            Digest certDigest = signingCertificateRef.getCertDigest();
            if (certDigest != null) {
                DigestAlgorithm digestAlgorithm = certDigest.getAlgorithm();
                if (DigestAlgorithm.SHA1.equals(digestAlgorithm)) {
                    if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, id_aa_signingCertificate)) == 0) {
                        return false;
                    }
                } else {
                    if (Utils.arraySize(CMSUtils.getSignedAttributes(signerInformation, id_aa_signingCertificateV2)) == 0) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

}
