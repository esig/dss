package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.status.SignatureStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to verify signature creation or augmentation requirements for PAdES signatures
 *
 */
public class PAdESSignatureRequirementsChecker extends SignatureRequirementsChecker {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESSignatureRequirementsChecker.class);

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param signatureParameters {@link PAdESSignatureParameters}
     */
    public PAdESSignatureRequirementsChecker(CertificateVerifier certificateVerifier, PAdESSignatureParameters signatureParameters) {
        super(certificateVerifier, signatureParameters);
    }

    @Override
    protected void checkTLevelIsHighest(AdvancedSignature signature, SignatureStatus status) {
        if (signature.hasLTAProfile()) {
            status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");

        } else if (signature.hasLTProfile() && !signature.areAllSelfSignedCertificates()) {
            if (signature.hasTProfile()) {
                status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");
            }
            // NOTE: Otherwise allow extension, as it may be required to provide a best-signature-time
            // to ensure the best practice of fresh revocation data incorporation
            LOG.info("Signature contains a DSS dictionary, but no associated timestamp. " +
                    "Extension may lead to LTA-level.");
        }
    }

}
