package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.cades.validation.CAdESBaselineRequirementsChecker;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class PAdESBaselineRequirementsChecker extends CAdESBaselineRequirementsChecker {

    /**
     * Default constructor
     *
     * @param signature                  {@link PAdESSignature}
     * @param offlineCertificateVerifier {@link CertificateVerifier}
     */
    public PAdESBaselineRequirementsChecker(PAdESSignature signature, CertificateVerifier offlineCertificateVerifier) {
        super(signature, offlineCertificateVerifier);
    }

}
