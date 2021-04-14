package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.validation.BaselineRequirementsChecker;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class JAdESBaselineRequirementsChecker extends BaselineRequirementsChecker<JAdESSignature> {

    /**
     * Default constructor
     *
     * @param signature                  {@link JAdESSignature} to validate
     * @param offlineCertificateVerifier {@link CertificateVerifier} offline copy of a used CertificateVerifier
     */
    public JAdESBaselineRequirementsChecker(JAdESSignature signature, CertificateVerifier offlineCertificateVerifier) {
        super(signature, offlineCertificateVerifier);
    }

    @Override
    public boolean hasBaselineBProfile() {
        return false;
    }

}
