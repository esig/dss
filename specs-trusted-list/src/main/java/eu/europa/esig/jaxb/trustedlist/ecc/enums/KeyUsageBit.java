package eu.europa.esig.jaxb.trustedlist.ecc.enums;

public enum KeyUsageBit {

	DIGITAL_SIGNATURE("digitalSignature"),

	NON_REPUDIATION("nonRepudiation"),

	KEY_ENCIPHERMENT("keyEncipherment"),

	DATA_ENCIPHERMENT("dataEncipherment"),

	KEY_AGREEMENT("keyAgreement"),

	KEY_CERT_SIGN("keyCertSign"),

	CRL_SIGN("crlSign"),

	ENCIPHER_ONLY("encipherOnly"),

	DECIPHER_ONLY("decipherOnly");

	private final String value;

	private KeyUsageBit(String value) {
		this.value = value;
	}

	public String getValue() {
		return value;
	}

}
