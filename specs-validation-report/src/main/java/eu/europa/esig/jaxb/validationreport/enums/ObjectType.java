package eu.europa.esig.jaxb.validationreport.enums;

public enum ObjectType implements UriBasedEnum {

	CERTIFICATE("urn:etsi:019102:validationObject:certificate"),

	CRL("urn:etsi:019102:validationObject:CRL"),

	OCSP_RESPONSE("urn:etsi:019102:validationObject:OCSPResponse"),

	TIMESTAMP("urn:etsi:019102:validationObject:timestamp"),

	EVIDENCE_RECORD("urn:etsi:019102:validationObject:evidencerecord"),

	PUBLIC_KEY("urn:etsi:019102:validationObject:publicKey"),

	SIGNED_DATA("urn:etsi:019102:validationObject:signedData"),

	OTHER("urn:etsi:019102:validationObject:other");

	private final String uri;

	ObjectType(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
