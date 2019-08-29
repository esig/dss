package eu.europa.esig.dss.xades;

public enum XMLDSigElement implements DSSElement {

	SIGNATURE("Signature"),

	SIGNATURE_VALUE("SignatureValue"),

	SIGNED_INFO("SignedInfo"),

	CANONICALIZATION_METHOD("CanonicalizationMethod"),

	SIGNATURE_METHOD("SignatureMethod"),

	HMAC_OUTPUT_LENGTH("HMACOutputLength"),

	REFERENCE("Reference"),

	TRANSFORMS("Transforms"), 
	
	TRANSFORM("Transform"),

	XPATH("XPath"),

	DIGEST_METHOD("DigestMethod"),

	DIGEST_VALUE("DigestValue"),

	KEY_INFO("KeyInfo"),

	KEY_NAME("KeyName"),

	MGMT_DATA("MgmtData"),

	KEY_VALUE("KeyValue"),

	RETRIEVAL_METHOD("RetrievalMethod"),

	X509_DATA("X509Data"),

	X509_ISSUER_SERIAL("X509IssuerSerial"),

	X509_SKI("X509SKI"),

	X509_SUBJECT_NAME("X509SubjectName"),

	X509_CERTIFICATE("X509Certificate"),

	X509_CRL("X509CRL"),

	X509_ISSUER_NAME("X509IssuerName"),

	X509_SERIAL_NUMBER("X509SerialNumber"),
	
	PGP_DATA("PGPData"),
	
	PGP_KEY_ID("PGPKeyID"),
	
	PGP_KEY_PACKET("PGPKeyPacket"),
	
	SPKI_DATA("SPKIData"),
	
	SPKI_SEXP("SPKISexp"),
	
	OBJECT("Object"),
	
	MANIFEST("Manifest"),
	
	SIGNATURE_PROPERTIES("SignatureProperties"),
	
	SIGNATURE_PROPERTY("SignatureProperty"),
	
	DSA_KEY_VALUE("DSAKeyValue"),

	P("P"),

	Q("Q"),

	G("G"),

	Y("Y"),

	J("J"),

	SEED("Seed"),

	PGEN_COUNTER("PgenCounter"),

	RSA_KEY_VALUE("RSAKeyValue"),

	MODULUS("Modulus"),

	EXPONENT("Exponent");

	private final String tagName;
	private final DSSNamespace namespace;

	XMLDSigElement(String tagName) {
		this.tagName = tagName;
		this.namespace = DSSNamespaces.XMLDSIG;
	}

	@Override
	public String getTagName() {
		return tagName;
	}

	@Override
	public DSSNamespace getNamespace() {
		return namespace;
	}

	@Override
	public String getURI() {
		return namespace.getUri();
	}

	@Override
	public boolean isSameTagName(String value) {
		return tagName.equals(value);
	}
}
