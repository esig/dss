package eu.europa.esig.dss.jades.requirements;

import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;

public class JAdESBaselineBSerialiazationTest extends AbstractJAdESSerializationSignatureRequirementsCheck {

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		return signatureParameters;
	}
	
	@Override
	protected void checkUnprotectedHeader(Map<?, ?> unprotectedHeader) throws Exception {
		assertNull(unprotectedHeader);
	}

}
