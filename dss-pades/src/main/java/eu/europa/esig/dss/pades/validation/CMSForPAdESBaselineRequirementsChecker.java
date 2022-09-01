package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.cades.validation.CAdESBaselineRequirementsChecker;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.SignatureForm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to verify conformance of a CMSSignedData to be incorporated to a PDF as a PAdES signature
 *
 */
public class CMSForPAdESBaselineRequirementsChecker extends CAdESBaselineRequirementsChecker {

    private static final Logger LOG = LoggerFactory.getLogger(CMSForPAdESBaselineRequirementsChecker.class);

    /**
     * Default constructor used to verify CMS of {@code CAdESSignature} on conformance to PAdES Baseline-B format
     *
     * @param signature {@link CAdESSignature} to be verified
     */
    public CMSForPAdESBaselineRequirementsChecker(CAdESSignature signature) {
        super(signature);
    }

    /**
     * This method verifies validity of a CMS signature for enveloping within a PDF signature of PAdES-BASELINE format
     *
     * @return TRUE if the CMS signature is conformant to PAdES-BASELINE format, FALSE otherwise
     */
    public boolean isValidForPAdESBaselineBProfile() {
        if (signature.getCmsSignedData().getSignerInfos().size() != 1) {
            LOG.warn("SignedData.signerInfos shall contain one and only one signerInfo for {}-BASELINE-B signature (cardinality == 1)!", getBaselineSignatureForm());
            return false;
        }
        return cmsBaselineBRequirements();
    }

    @Override
    protected SignatureForm getBaselineSignatureForm() {
        return SignatureForm.PAdES;
    }

}
