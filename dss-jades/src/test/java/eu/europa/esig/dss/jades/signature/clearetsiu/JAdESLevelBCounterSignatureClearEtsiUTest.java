package eu.europa.esig.dss.jades.signature.clearetsiu;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESLevelBCounterSignatureTest;

public class JAdESLevelBCounterSignatureClearEtsiUTest extends JAdESLevelBCounterSignatureTest {

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setBase64UrlEncodedEtsiUComponents(false);
		return signatureParameters;
	}

}
