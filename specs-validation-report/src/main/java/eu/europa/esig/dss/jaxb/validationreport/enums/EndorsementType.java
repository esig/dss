package eu.europa.esig.dss.jaxb.validationreport.enums;

public enum EndorsementType {
	
	CERTIFIED("certified"),
	
	CLAIMED("claimed"),
	
	SIGNED("signed");
	
	private final String value;
	
	private EndorsementType(String value) {
		this.value = value;
	}

	public String getValue() {
		return value;
	}

	public static EndorsementType fromString(String value) {
		for (EndorsementType endorsement : values()) {
			if (endorsement.value.equals(value)) {
				return endorsement;
			}
		}
		return null;
	}

}
