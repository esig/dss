package eu.europa.esig.dss.jades.signature.counter;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;

public class JAdESCounterSignatureParameters extends JAdESSignatureParameters implements SerializableCounterSignatureParameters {
	
	/**
	 * Signature Id to be counter signed
	 */
	private String signatureId;

	@Override
	public String getSigningSignatureId() {
		return signatureId;
	}
	
	@Override
	public void setSigningSignatureId(String signatureId) {
		this.signatureId = signatureId;
	}
	
	@Override
	public SignaturePackaging getSignaturePackaging() {
		return SignaturePackaging.DETACHED;
	}
	
	@Override
	public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
		throw new IllegalArgumentException("The signaturePackaging parameter is not supported for a Counter JAdES Signature!");
	}
	
	@Override
	public SigDMechanism getSigDMechanism() {
		return SigDMechanism.NO_SIG_D;
	}
	
	@Override
	public void setSigDMechanism(SigDMechanism sigDMechanism) {
		throw new IllegalArgumentException("The sigDMechanism parameter is not supported for a Counter JAdES Signature!");
	}
	
	@Override
	public void setJwsSerializationType(JWSSerializationType jwsSerializationType) {
		if (JWSSerializationType.JSON_SERIALIZATION.equals(jwsSerializationType)) {
			throw new IllegalArgumentException("The JWSSerializationType.JSON_SERIALIZATION parameter is not supported for a Counter JAdES Signature!");
		}
		super.setJwsSerializationType(jwsSerializationType);
	}

}
