package eu.europa.esig.dss.jaxb.validationreport.enums;

public enum SubIndication implements UriBasedEnum {

	FORMAT_FAILURE("urn:etsi:019102:subindication:FORMAT_FAILURE"),

	HASH_FAILURE("urn:etsi:019102:subindication:HASH_FAILURE"),

	SIG_CRYPTO_FAILURE("urn:etsi:019102:subindication:SIG_CRYPTO_FAILURE"),

	REVOKED("urn:etsi:019102:subindication:REVOKED"),

	SIG_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:SIG_CONSTRAINTS_FAILURE"),

	CHAIN_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:CHAIN_CONSTRAINTS_FAILURE"),

	CERTIFICATE_CHAIN_GENERAL_FAILURE("urn:etsi:019102:subindication:CERTIFICATE_CHAIN_GENERAL_FAILURE"),

	CRYPTO_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE"),

	EXPIRED("urn:etsi:019102:subindication:EXPIRED"),

	NOT_YET_VALID("urn:etsi:019102:subindication:NOT_YET_VALID"),

	POLICY_PROCESSING_ERROR("urn:etsi:019102:subindication:POLICY_PROCESSING_ERROR"),

	SIGNATURE_POLICY_NOT_AVAILABLE("urn:etsi:019102:subindication:SIGNATURE_POLICY_NOT_AVAILABLE"),

	TIMESTAMP_ORDER_FAILURE("urn:etsi:019102:subindication:TIMESTAMP_ORDER_FAILURE"),

	NO_SIGNING_CERTIFICATE_FOUND("urn:etsi:019102:subindication:NO_SIGNING_CERTIFICATE_FOUND"),

	NO_CERTIFICATE_CHAIN_FOUND("urn:etsi:019102:subindication:NO_CERTIFICATE_CHAIN_FOUND"),

	REVOKED_NO_POE("urn:etsi:019102:subindication:REVOKED_NO_POE"),

	REVOKED_CA_NO_POE("urn:etsi:019102:subindication:REVOKED_CA_NO_POE"),

	OUT_OF_BOUNDS_NO_POE("urn:etsi:019102:subindication:OUT_OF_BOUNDS_NO_POE"),

	CRYPTO_CONSTRAINTS_FAILURE_NO_POE("urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),

	NO_POE("urn:etsi:019102:subindication:NO_POE"),

	TRY_LATER("urn:etsi:019102:subindication:TRY_LATER"),

	SIGNED_DATA_NOT_FOUND("urn:etsi:019102:subindication:SIGNED_DATA_NOT_FOUND");

	private final String uri;

	private SubIndication(String uri) {
		this.uri = uri;
	}

	public String getUri() {
		return uri;
	}

}
