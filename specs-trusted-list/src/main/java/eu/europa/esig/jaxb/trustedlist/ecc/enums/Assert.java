package eu.europa.esig.jaxb.trustedlist.ecc.enums;

public enum Assert {

	ALL("all"),

	AT_LEAST_ONE("atLeastOne"),

	NONE("none");

	private final String value;

	Assert(String value) {
		this.value = value;
	}

	public String getValue() {
		return value;
	}

}
