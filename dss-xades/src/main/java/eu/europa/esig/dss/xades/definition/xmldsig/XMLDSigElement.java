package eu.europa.esig.dss.xades.definition.xmldsig;

import eu.europa.esig.dss.xades.definition.DSSElement;
import eu.europa.esig.dss.xades.definition.DSSNamespace;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;

public enum XMLDSigElement implements DSSElement {

	CANONICALIZATION_METHOD("CanonicalizationMethod"),

	DIGEST_METHOD("DigestMethod"),

	DIGEST_VALUE("DigestValue"),

	DSA_KEY_VALUE("DSAKeyValue"),

	EXPONENT("Exponent"),

	G("G"),

	HMAC_OUTPUT_LENGTH("HMACOutputLength"),

	J("J"), 
	
	KEY_INFO("KeyInfo"),

	KEY_NAME("KeyName"),

	KEY_VALUE("KeyValue"),

	MANIFEST("Manifest"),

	MGMT_DATA("MgmtData"),

	MODULUS("Modulus"),

	OBJECT("Object"),

	P("P"),

	PGEN_COUNTER("PgenCounter"),

	PGP_DATA("PGPData"),

	PGP_KEY_ID("PGPKeyID"),

	PGP_KEY_PACKET("PGPKeyPacket"),

	Q("Q"),

	REFERENCE("Reference"),

	RETRIEVAL_METHOD("RetrievalMethod"),

	RSA_KEY_VALUE("RSAKeyValue"),

	SEED("Seed"),
	
	SIGNATURE("Signature"),
	
	SIGNATURE_METHOD("SignatureMethod"),
	
	SIGNATURE_PROPERTIES("SignatureProperties"),
	
	SIGNATURE_PROPERTY("SignatureProperty"),
	
	SIGNATURE_VALUE("SignatureValue"),
	
	SIGNED_INFO("SignedInfo"),
	
	SPKI_DATA("SPKIData"),
	
	SPKI_SEXP("SPKISexp"),
	
	TRANSFORM("Transform"),
	
	TRANSFORMS("Transforms"),

	X509_CERTIFICATE("X509Certificate"),

	X509_CRL("X509CRL"),

	X509_DATA("X509Data"),

	X509_ISSUER_NAME("X509IssuerName"),

	X509_ISSUER_SERIAL("X509IssuerSerial"),

	X509_SERIAL_NUMBER("X509SerialNumber"),

	X509_SKI("X509SKI"),

	X509_SUBJECT_NAME("X509SubjectName"),

	XPATH("XPath"),

	Y("Y");

	private final DSSNamespace namespace;
	private final String tagName;

	XMLDSigElement(String tagName) {
		this.tagName = tagName;
		this.namespace = XAdESNamespaces.XMLDSIG;
	}

	@Override
	public DSSNamespace getNamespace() {
		return namespace;
	}

	@Override
	public String getTagName() {
		return tagName;
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
