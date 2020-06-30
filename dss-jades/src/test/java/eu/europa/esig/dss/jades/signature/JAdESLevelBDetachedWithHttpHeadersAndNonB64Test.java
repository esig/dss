package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;

public class JAdESLevelBDetachedWithHttpHeadersAndNonB64Test extends JAdESLevelBDetachedWithHttpHeadersMechanismTest {

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setBase64UrlEncodedPayload(false);
		return signatureParameters;
	}

}
