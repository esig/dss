package eu.europa.esig.dss.enumerations;

public enum SignatureValidity {
	
	VALID, INVALID, NOT_EVALUATED;
	
	public static SignatureValidity get(Boolean isValid) {
		if (isValid == null) {
			return NOT_EVALUATED;
		} else if (isValid) {
			return VALID;
		} else {
			return INVALID;
		}
	}

}
