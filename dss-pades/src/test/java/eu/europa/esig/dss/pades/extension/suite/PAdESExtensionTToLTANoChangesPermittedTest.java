package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.pades.CertificationPermission;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;

public class PAdESExtensionTToLTANoChangesPermittedTest extends AbstractPAdESTestExtension {

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        PAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setPermission(CertificationPermission.NO_CHANGE_PERMITTED);
        return signatureParameters;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_T;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_LTA;
    }

}
