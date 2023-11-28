package eu.europa.esig.dss.xades.extension.prettyprint;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.extension.XAdESExtensionLTWithTSVDToLTATest;

public class XAdESExtensionLTPrettyPrintWithTSVDToLTAPrettyPrintTest extends XAdESExtensionLTWithTSVDToLTATest {

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setPrettyPrint(true);
        return signatureParameters;
    }

    @Override
    protected XAdESSignatureParameters getExtensionParameters() {
        XAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setPrettyPrint(true);
        return extensionParameters;
    }

}
