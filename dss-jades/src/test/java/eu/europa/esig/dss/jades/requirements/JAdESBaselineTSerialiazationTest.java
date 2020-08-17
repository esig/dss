package eu.europa.esig.dss.jades.requirements;

import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;

public class JAdESBaselineTSerialiazationTest extends AbstractJAdESSerializationSignatureRequirementsCheck {

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_T);
		return signatureParameters;
	}
	
	@Override
	protected void checkCertificateValues(Map<?, ?> unprotectedHeaderMap) {
		List<?> xVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "xVals");
		assertNull(xVals);
		
		List<?> axVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "axVals");
		assertNull(axVals);
	}
	
	@Override
	protected void checkRevocationValues(Map<?, ?> unprotectedHeaderMap) {
		List<?> rVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "rVals");
		assertNull(rVals);
		
		List<?> arVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "arVals");
		assertNull(arVals);
	}
	
	@Override
	protected void checkArchiveTimestamp(Map<?, ?> unprotectedHeaderMap) {
		List<?> arcTst = (List<?>) getEtsiUElement(unprotectedHeaderMap, "arcTst");
		assertNull(arcTst);
	}

}
