package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A container with JWS signature attributes
 */
public class JWSJsonSerializationObject {
	
	/** The JWS payload */
	private String payload;
	
	/** The list of incorporated signatures */
	private List<JWS> signatures;
	
	/** Defines the JWSSerializationType of the JAdES signature */
	private JWSSerializationType jwsSerializationType;
	
	/** A list of parsing errors if occurred */
	private List<String> structuralValidationErrors;

	/**
	 * Gets the base64url encoded payload of a signature
	 *
	 * @return {@link String} base64url encoded payload
	 */
	public String getPayload() {
		if (payload == null) {
			payload = Utils.EMPTY_STRING;
		}
		return payload;
	}

	/**
	 * Sets the base64url encoded payload of a signature
	 *
	 * @param encodedPayload {@link String} base64url encoded payload
	 */
	public void setPayload(String encodedPayload) {
		this.payload = encodedPayload;
	}

	public List<JWS> getSignatures() {
		if (signatures == null) {
			signatures = new ArrayList<>();
		}
		return signatures;
	}

	/**
	 * Sets a list of signatures
	 *
	 * @param signatures a list of {@link JWS}
	 */
	public void setSignatures(List<JWS> signatures) {
		this.signatures = signatures;
	}

	/**
	 * Gets the used {@code JWSSerializationType} for the signature
	 *
	 * @return {@link JWSSerializationType}
	 */
	public JWSSerializationType getJWSSerializationType() {
		return jwsSerializationType;
	}

	/**
	 * Sets the {@code JWSSerializationType}
	 *
	 * @param jwsSerializationType {@link JWSSerializationType}
	 */
	public void setJWSSerializationType(JWSSerializationType jwsSerializationType) {
		if (!JWSSerializationType.JSON_SERIALIZATION.equals(jwsSerializationType) &&
				!JWSSerializationType.FLATTENED_JSON_SERIALIZATION.equals(jwsSerializationType)) {
			throw new IllegalArgumentException(String.format("The JWSSerializationType '%s' is not supported for the JWSJsonSerializationObject", 
					jwsSerializationType));
		}
		this.jwsSerializationType = jwsSerializationType;
	}

	/**
	 * Returns a list of errors occurred during the structure (schema) validation
	 *
	 * @return a list of {@link String} error messages, empty list if no errors have been found
	 */
	public List<String> getStructuralValidationErrors() {
		if (Utils.isCollectionNotEmpty(structuralValidationErrors)) {
			return structuralValidationErrors;
		}
		return Collections.emptyList();
	}

	/**
	 * Sets a list of errors occurred during the structure (schema) validation
	 *
	 * @param structuralValidationErrors a list of {@link String} error messages
	 */
	public void setStructuralValidationErrors(List<String> structuralValidationErrors) {
		this.structuralValidationErrors = structuralValidationErrors;
	}

	/**
	 * Checks if the signature structure validation succeeded
	 *
	 * @return TRUE if the structure validation succeeded, FALSE otherwise
	 */
	public boolean isValid() {
		return Utils.isCollectionEmpty(structuralValidationErrors);
	}

}
