package eu.europa.esig.dss.jades;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.utils.Utils;

public class JWSJsonSerializationObject {
	
	/** The JWS payload */
	private String payload;
	
	/** The list of incorporated signatures */
	private List<JWS> signatures;
	
	/** Defines the JWSSerializationType of the JAdES signature */
	private JWSSerializationType jwsSerializationType;
	
	/** A list of parsing errors if occurred */
	private List<String> structuralValidationErrors;

	public String getPayload() {
		if (payload == null) {
			payload = Utils.EMPTY_STRING;
		}
		return payload;
	}

	public void setPayload(String encodedPayload) {
		this.payload = encodedPayload;
	}

	public List<JWS> getSignatures() {
		if (signatures == null) {
			signatures = new ArrayList<>();
		}
		return signatures;
	}

	public void setSignatures(List<JWS> signatures) {
		this.signatures = signatures;
	}

	public JWSSerializationType getJWSSerializationType() {
		return jwsSerializationType;
	}

	public void setJWSSerializationType(JWSSerializationType jwsSerializationType) {
		if (!JWSSerializationType.JSON_SERIALIZATION.equals(jwsSerializationType) &&
				!JWSSerializationType.FLATTENED_JSON_SERIALIZATION.equals(jwsSerializationType)) {
			throw new IllegalArgumentException(String.format("The JWSSerializationType '%s' is not supported for the JWSJsonSerializationObject", 
					jwsSerializationType));
		}
		this.jwsSerializationType = jwsSerializationType;
	}
	
	public List<String> getStructuralValidationErrors() {
		return structuralValidationErrors;
	}
	
	public void setStructuralValidationErrors(List<String> structuralValidationErrors) {
		this.structuralValidationErrors = structuralValidationErrors;
	}
	
	public boolean isValid() {
		return Utils.isCollectionNotEmpty(structuralValidationErrors);
	}

}
