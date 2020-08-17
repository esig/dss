package eu.europa.esig.dss.jades.requirements;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;

public class JAdESBaselineLTASerialiazationTest extends AbstractJAdESSerializationSignatureRequirementsCheck {

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
		return signatureParameters;
	}

}
