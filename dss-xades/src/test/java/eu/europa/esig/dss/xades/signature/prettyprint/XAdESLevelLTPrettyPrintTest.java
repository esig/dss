package eu.europa.esig.dss.xades.signature.prettyprint;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESLevelLTTest;

public class XAdESLevelLTPrettyPrintTest extends XAdESLevelLTTest {

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setPrettyPrint(true);
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return RSA_SHA3_USER;
    }

}
