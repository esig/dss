package eu.europa.esig.dss.jades;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.utils.Utils;

public class JWSJsonSerializationObject {
	
	/** The JWS payload */
	private String payload;
	
	/** The list of incorporated signatures */
	private List<JWS> signatures;
	
	/** TRUE when the parsed file is a flattened signature type, FALSE otherwise */
	private boolean flattened;
	
	/** A list of parsing errors if occurred */
	private List<String> errors = new ArrayList<>();

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

	public boolean isFlattened() {
		return flattened;
	}

	public void setFlattened(boolean flattened) {
		this.flattened = flattened;
	}
	
	public void addErrorMessage(String error) {
		errors.add(error);
	}
	
	public String getErrorMessages() {
		return String.join("; ", errors);
	}
	
	public boolean isValid() {
		return Utils.isCollectionEmpty(errors);
	}

}
