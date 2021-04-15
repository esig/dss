package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.BaselineRequirementsChecker;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
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
        if (!signature.isCounterSignature() &&
                CMSUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_contentType) == null) {
            LOG.warn("content-type attribute shall be present for {}-BASELINE-B signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // message-digest (Cardinality == 1)
        if (CMSUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_messageDigest) == null) {
            LOG.warn("message-digest attribute shall be present for {}-BASELINE-B signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // signing-certificate/signing-certificate-v2 (Cardinality == 1)
        if (!(CMSUtils.getSignedAttribute(signerInformation, id_aa_signingCertificate) != null ^
                CMSUtils.getSignedAttribute(signerInformation, id_aa_signingCertificateV2) != null)) {
            LOG.warn("signing-certificate(-v2) attribute shall be present for {}-BASELINE-B signature (cardinality == 1)!", signatureForm);
            return false;
        }
        // signing-time (Cardinality == 1)
        boolean signingTimePresent = CMSUtils.getSignedAttribute(
                signerInformation, PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null;
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
        // Additional requirement (h) and (i)
        List<CertificateRef> certificateRefs = signature.getCertificateSource().getSigningCertificateRefs();
        if (Utils.isCollectionNotEmpty(certificateRefs)) {
            CertificateRef signingCertificateRef = certificateRefs.iterator().next(); // only one shall be used
            Digest certDigest = signingCertificateRef.getCertDigest();
            if (certDigest != null) {
                DigestAlgorithm digestAlgorithm = certDigest.getAlgorithm();
                if (DigestAlgorithm.SHA1.equals(digestAlgorithm)) {
                    if (CMSUtils.getSignedAttribute(signerInformation, id_aa_signingCertificate) == null) {
                        LOG.warn("signing-certificate attribute shall be used for SHA1 hash algorithm " +
                                "for {}-BASELINE-B signature (requirement (h) 319 122-1)!", signatureForm);
                        return false;
                    }
                } else {
                    if (CMSUtils.getSignedAttribute(signerInformation, id_aa_signingCertificateV2) == null) {
                        LOG.warn("signing-certificate-v2 attribute shall be used for SHA1 hash algorithm " +
                                "for {}-BASELINE-B signature (requirement (i) 319 122-1)!", signatureForm);
                        return false;
                    }
                }
            }
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
        return minimalTRequirement();
    }

    @Override
    public boolean hasBaselineLTProfile() {
        if (!minimalLTRequirement()) {
            return false;
        }
        SignerInformation signerInformation = signature.getSignerInformation();
        // certificate-values (Cardinality == 0)
        if (CMSUtils.getUnsignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certValues) != null) {
            LOG.warn("certificate-values attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // complete-certificate-references (Cardinality == 0)
        if (CMSUtils.getUnsignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certificateRefs) != null) {
            LOG.warn("complete-certificate-references attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // revocation-values (Cardinality == 0)
        if (CMSUtils.getUnsignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null) {
            LOG.warn("revocation-values attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // complete-revocation-references (Cardinality == 0)
        if (CMSUtils.getUnsignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_revocationRefs) != null) {
            LOG.warn("complete-revocation-references attribute shall not be present " +
                    "for CAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // time-stamped-certs-crls-references (Cardinality == 0)
        if (CMSUtils.getUnsignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp) != null) {
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
                    ArchiveTimestampType.CAdES_DETACHED.equals(timestampToken.getArchiveTimestampType())) {
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
     * Checks if the signature has a corresponding CAdES-C profile
     *
     * @return TRUE if the signature has a CAdES-C profile, FALSE otherwise
     */
    public boolean hasExtendedCProfile() {
        SignerInformation signerInformation = signature.getSignerInformation();
        // complete-certificate-references
        if (CMSUtils.getUnsignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_certificateRefs) == null) {
            LOG.debug("complete-certificate-references attribute shall be present for CAdES-C signature (cardinality == 1)!");
            return false;
        }
        // complete-revocation-references
        ListCertificateSource certificateSources = getCertificateSourcesExceptLastArchiveTimestamp();
        boolean allSelfSigned = certificateSources.isAllSelfSigned();
        if (!allSelfSigned &&
                CMSUtils.getUnsignedAttribute(signerInformation, PKCSObjectIdentifiers.id_aa_ets_revocationRefs) == null) {
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
        if (CMSUtils.getUnsignedAttribute(signerInformation, id_aa_ets_certCRLTimestamp) == null &&
                CMSUtils.getUnsignedAttribute(signerInformation, id_aa_ets_escTimeStamp) == null) {
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

}
