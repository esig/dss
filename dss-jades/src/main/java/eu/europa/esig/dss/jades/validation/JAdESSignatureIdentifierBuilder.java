package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.validation.AbstractSignatureIdentifierBuilder;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class JAdESSignatureIdentifierBuilder extends AbstractSignatureIdentifierBuilder {

	public JAdESSignatureIdentifierBuilder(JAdESSignature signature) {
		super(signature);
	}

	@Override
	protected Integer getCounterSignaturePosition(AdvancedSignature masterSignature) {
		JAdESSignature jadesSignature = (JAdESSignature) signature;
		JAdESSignature jadesMasterSignature = (JAdESSignature) masterSignature;
		Object masterCSigObject = jadesSignature.getMasterCSigObject();

		int counter = 0;
		if (masterCSigObject != null) {
			for (AdvancedSignature counterSignature : jadesMasterSignature.getCounterSignatures()) {
				JAdESSignature jadesCounterSignature = (JAdESSignature) counterSignature;
				if (masterCSigObject == jadesCounterSignature.getMasterCSigObject()) {
					break;
				}
				++counter;
			}
		}
		
		return counter;
	}

	@Override
	protected Integer getSignatureFilePosition() {
		JAdESSignature jadesSignature = (JAdESSignature) signature;
		JWS currentJWS = jadesSignature.getJws();
		JWSJsonSerializationObject jwsJsonSerializationObject = jadesSignature.getJws().getJwsJsonSerializationObject();
		
		int counter = 0;
		if (jwsJsonSerializationObject != null) {
			for (JWS jws : jwsJsonSerializationObject.getSignatures()) {
				if (currentJWS == jws) {
					break;
				}
				++counter;
			}
		}
		
		return counter;
	}

}
