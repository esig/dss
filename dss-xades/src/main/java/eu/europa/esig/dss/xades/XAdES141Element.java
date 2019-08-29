package eu.europa.esig.dss.xades;

public enum XAdES141Element implements DSSElement {

	TIMESTAMP_VALIDATION_DATA("TimeStampValidationData"),

	SIGNATURE_POLICY_STORE("SignaturePolicyStore"),

	SIGNATURE_POLICY_DOCUMENT("SignaturePolicyDocument"),

	SIG_POL_DOC_LOCAL_URI("SigPolDocLocalURI"),
	
	SP_DOC_SPECIFICATION("SPDocSpecification"),

	RENEWED_DIGESTS("RenewedDigests"),

	RECOMPUTED_DIGEST_VALUE("RecomputedDigestValue"),

	ARCHIVE_TIMESTAMP("ArchiveTimeStamp"),

	COMPLETE_CERTIFICATE_REFS_V2("CompleteCertificateRefsV2"),

	ATTRIBUTE_CERTIFICATE_REFS_V2("AttributeCertificateRefsV2"),

	CERT_REFS("CertRefs"),

	SIG_AND_REFS_TIMESTAMP_V2("SigAndRefsTimeStampV2"),

	REFS_ONLY_TIMESTAMP_V2("RefsOnlyTimeStampV2");

	private final String tagName;
	private final DSSNamespace namespace;

	XAdES141Element(String tagName) {
		this.tagName = tagName;
		this.namespace = DSSNamespaces.XADES_141;
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
