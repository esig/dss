package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
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

    @Override
    public boolean hasBaselineBProfile() {
        CMSSignedData cmsSignedData = signature.getCmsSignedData();
        SignerInformation signerInformation = signature.getSignerInformation();
        // SignedData.certificates (Cardinality == 1)
        if (Utils.isCollectionEmpty(cmsSignedData.getCertificates().getMatches(null))) {
            LOG.warn("SignedData.certificates shall be present for CAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // content-type (Cardinality == 1)
        if (!signature.isCounterSignature() &&
                CMSUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_contentType) == null) {
            LOG.warn("content-type attribute shall be present for CAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // message-digest (Cardinality == 1)
        if (CMSUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_messageDigest) == null) {
            LOG.warn("message-digest attribute shall be present for CAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // signing-certificate/signing-certificate-v2 (Cardinality == 1)
        if (!(CMSUtils.getSignedAttribute(signerInformation, id_aa_signingCertificate) != null ^
                CMSUtils.getSignedAttribute(signerInformation, id_aa_signingCertificateV2) != null)) {
            LOG.warn("signing-certificate(-v2) attribute shall be present for CAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // signing-time (Cardinality == 1)
        if (CMSUtils.getSignedAttribute(signerInformation, PKCSObjectIdentifiers.pkcs_9_at_signingTime) == null) {
            LOG.warn("signing-time attribute shall be present for CAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // Additional requirement (a)
        if (!containsSigningCertificate(signature.getCertificateSource().getSignedDataCertificates())) {
            LOG.warn("Signing certificate shall be present in SignedData.certificates " +
                    "for CAdES-BASELINE-B signature (requirement (a))!");
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
                                "for CAdES-BASELINE-B signature (requirement (h))!");
                        return false;
                    }
                } else {
                    if (CMSUtils.getSignedAttribute(signerInformation, id_aa_signingCertificateV2) == null) {
                        LOG.warn("signing-certificate-v2 attribute shall be used for SHA1 hash algorithm " +
                                "for CAdES-BASELINE-B signature (requirement (i))!");
                        return false;
                    }
                }
            }
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
    public boolean hasBaselineLTProfile() {
        if (!super.hasBaselineLTProfile()) {
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
        if (!super.hasBaselineLTAProfile()) {
            return false;
        }
        // archive-time-stamp-v3 (Cardinality == 0)
        boolean archiveTstV3Found = false;
        for (TimestampToken timestampToken : signature.getArchiveTimestamps()) {
            if (ArchiveTimestampType.CAdES_V3.equals(timestampToken.getArchiveTimestampType())) {
                archiveTstV3Found = true;
                break;
            }
        }
        if (!archiveTstV3Found) {
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
        // minimal LT requirement check
        return super.hasBaselineLTProfile();
    }

    /**
     * Checks if the signature has a corresponding CAdES-A profile
     *
     * @return TRUE if the signature has a CAdES-A profile, FALSE otherwise
     */
    public boolean hasExtendedAProfile() {
        // minimal LTA requirement check
        return super.hasBaselineLTAProfile();
    }

}
