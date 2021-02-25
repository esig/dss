package eu.europa.esig.dss.xades.signature.prettyprint;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESLevelXLv2Test;

public class XAdESLevelXLPrettyPrintTest extends XAdESLevelXLv2Test {

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setPrettyPrint(true);
        return signatureParameters;
    }

}
