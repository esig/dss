package eu.europa.esig.dss.xades.definition.xades141;

import eu.europa.esig.dss.xades.definition.DSSElement;
import eu.europa.esig.dss.xades.definition.DSSNamespace;
import eu.europa.esig.dss.xades.definition.DSSNamespaces;

public enum XAdES141Element implements DSSElement {

	ARCHIVE_TIMESTAMP("ArchiveTimeStamp"),

	ATTRIBUTE_CERTIFICATE_REFS_V2("AttributeCertificateRefsV2"),

	CERT_REFS("CertRefs"),

	COMPLETE_CERTIFICATE_REFS_V2("CompleteCertificateRefsV2"),
	
	RECOMPUTED_DIGEST_VALUE("RecomputedDigestValue"),

	REFS_ONLY_TIMESTAMP_V2("RefsOnlyTimeStampV2"),

	RENEWED_DIGESTS("RenewedDigests"),

	SIG_AND_REFS_TIMESTAMP_V2("SigAndRefsTimeStampV2"),

	SIG_POL_DOC_LOCAL_URI("SigPolDocLocalURI"),

	SIGNATURE_POLICY_DOCUMENT("SignaturePolicyDocument"),

	SIGNATURE_POLICY_STORE("SignaturePolicyStore"),

	SP_DOC_SPECIFICATION("SPDocSpecification"),

	TIMESTAMP_VALIDATION_DATA("TimeStampValidationData");

	private final DSSNamespace namespace;
	private final String tagName;

	XAdES141Element(String tagName) {
		this.tagName = tagName;
		this.namespace = DSSNamespaces.XADES_141;
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
