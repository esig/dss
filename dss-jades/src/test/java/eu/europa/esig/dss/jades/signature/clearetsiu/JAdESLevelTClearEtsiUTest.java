package eu.europa.esig.dss.jades.signature.clearetsiu;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESLevelTFlattenedSerializationTest;

public class JAdESLevelTClearEtsiUTest extends JAdESLevelTFlattenedSerializationTest {

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setBase64UrlEncodedEtsiUComponents(false);
		return signatureParameters;
	}

}
