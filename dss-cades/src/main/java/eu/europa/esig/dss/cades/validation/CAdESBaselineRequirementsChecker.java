package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.validation.BaselineRequirementsChecker;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class CAdESBaselineRequirementsChecker extends BaselineRequirementsChecker<CAdESSignature> {

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
        return false;
    }

}
