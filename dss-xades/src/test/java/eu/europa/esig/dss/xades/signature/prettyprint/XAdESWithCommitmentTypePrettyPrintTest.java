package eu.europa.esig.dss.xades.signature.prettyprint;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESLevelBWithCustomCommitmentTypeTest;

public class XAdESWithCommitmentTypePrettyPrintTest extends XAdESLevelBWithCustomCommitmentTypeTest {

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setPrettyPrint(true);
		return signatureParameters;
	}

}
