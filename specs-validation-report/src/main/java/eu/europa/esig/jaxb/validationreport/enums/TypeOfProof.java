package eu.europa.esig.jaxb.validationreport.enums;

public enum TypeOfProof implements UriBasedEnum {

	/**
	 * when the POE has been derived during validation
	 */
	VALIDATION("urn:etsi:019102:poetype:validation"),

	/**
	 * when the POE has been provided to the SVA as an input
	 */
	PROVIDED("urn:etsi:019102:poetype:provided"),

	/**
	 * when the POE has been derived by the policy
	 */
	POLICY("urn:etsi:019102:poetype:policy");

	private final String uri;

	private TypeOfProof(String uri) {
		this.uri = uri;
	}

	public String getUri() {
		return uri;
	}

}
