package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.cades.validation.CAdESBaselineRequirementsChecker;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        PdfSignatureRevision pdfRevision = padesSignature.getPdfRevision();
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
            LOG.warn("Entry with a key SubFilter contain a value ETSI.CAdES.detached " +
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
        return true;
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
        return coversLTLevelData(timestampToken) && containsRFC3161SubFilter(timestampToken);
    }

    private boolean coversLTLevelData(TimestampToken timestampToken) {
        return ArchiveTimestampType.PAdES.equals(timestampToken.getArchiveTimestampType());
    }

    private boolean containsRFC3161SubFilter(TimestampToken timestampToken) {
        if (timestampToken instanceof PdfTimestampToken) {
            PdfDocTimestampRevision pdfRevision = ((PdfTimestampToken) timestampToken).getPdfRevision();
            if (pdfRevision != null) {
                PdfSignatureDictionary pdfSigDictInfo = pdfRevision.getPdfSigDictInfo();
                if (pdfSigDictInfo != null && PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(pdfSigDictInfo.getSubFilter())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the signature has PKCS#7 profile
     *
     * @return TRUE if the signature has a PKCS#7 profile, FALSE otherwise
     */
    public boolean hasPKCS7Profile() {
        PAdESSignature padesSignature = (PAdESSignature) signature;
        PdfSignatureDictionary pdfSignatureDictionary = padesSignature.getPdfSignatureDictionary();
        if (!PAdESConstants.SIGNATURE_PKCS7_SUBFILTER.equals(pdfSignatureDictionary.getSubFilter()) &&
                !PAdESConstants.SIGNATURE_PKCS7_SHA1_SUBFILTER.equals(pdfSignatureDictionary.getSubFilter())) {
            LOG.debug("Entry with a key SubFilter shall have a value adbe.pkcs7.detached or adbe.pkcs7.sha1 " +
                    "for PKCS#7 signature!");
            return false;
        }
        if (!containsSigningCertificate(padesSignature.getCertificateSource().getCertificates())) {
            LOG.warn("PKCS#7 signature shall include signing certificate!");
            return false;
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
        return minimalLTRequirement();
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
