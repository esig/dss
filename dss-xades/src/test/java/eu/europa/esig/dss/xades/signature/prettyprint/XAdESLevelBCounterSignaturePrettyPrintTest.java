package eu.europa.esig.dss.xades.signature.prettyprint;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESLevelBEnvelopingCounterSignatureTest;

public class XAdESLevelBCounterSignaturePrettyPrintTest extends XAdESLevelBEnvelopingCounterSignatureTest {

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setPrettyPrint(true);
		return signatureParameters;
	}

	@Override
	protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
		XAdESCounterSignatureParameters signatureParameters = super.getCounterSignatureParameters();
		signatureParameters.setPrettyPrint(true);
		return signatureParameters;
	}

}
