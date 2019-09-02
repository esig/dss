package eu.europa.esig.dss.xades.definition.xades132;

import eu.europa.esig.dss.xades.definition.DSSElement;
import eu.europa.esig.dss.xades.definition.DSSNamespace;
import eu.europa.esig.dss.xades.definition.DSSNamespaces;

public enum XAdES132Element implements DSSElement {

	ALL_DATA_OBJECTS_TIMESTAMP("AllDataObjectsTimeStamp"),

	ALL_SIGNED_DATA_OBJECTS("AllSignedDataObjects"),

	ANY("Any"),

	ARCHIVE_TIMESTAMP("ArchiveTimeStamp"),

	ATTR_AUTHORITIES_CERT_VALUES("AttrAuthoritiesCertValues"),

	ATTRIBUTE_CERTIFICATE_REFS("AttributeCertificateRefs"),

	ATTRIBUTE_REVOCATION_REFS("AttributeRevocationRefs"),

	ATTRIBUTE_REVOCATION_VALUES("AttributeRevocationValues"),

	BY_KEY("ByKey"),

	BY_NAME("ByName"),

	CERT("Cert"),

	CERT_DIGEST("CertDigest"),

	CERT_REFS("CertRefs"),

	CERTIFICATE_VALUES("CertificateValues"),

	CERTIFIED_ROLE("CertifiedRole"),

	CERTIFIED_ROLES("CertifiedRoles"),

	CERTIFIED_ROLES_V2("CertifiedRolesV2"),

	CITY("City"),

	CLAIMED_ROLE("ClaimedRole"),

	CLAIMED_ROLES("ClaimedRoles"),

	COMMITMENT_TYPE_ID("CommitmentTypeId"),

	COMMITMENT_TYPE_INDICATION("CommitmentTypeIndication"),

	COMMITMENT_TYPE_QUALIFIER("CommitmentTypeQualifier"),

	COMMITMENT_TYPE_QUALIFIERS("CommitmentTypeQualifiers"),

	COMPLETE_CERTIFICATE_REFS("CompleteCertificateRefs"),

	COMPLETE_REVOCATION_REFS("CompleteRevocationRefs"),

	COUNTER_SIGNATURE("CounterSignature"),

	COUNTRY_NAME("CountryName"),

	CRL_IDENTIFIER("CRLIdentifier"),

	CRL_REF("CRLRef"),

	CRL_REFS("CRLRefs"),

	CRL_VALUES("CRLValues"),

	DATA_OBJECT_FORMAT("DataObjectFormat"),

	DESCRIPTION("Description"),

	DIGEST_ALG_AND_VALUE("DigestAlgAndValue"),

	DOCUMENTATION_REFERENCE("DocumentationReference"),

	DOCUMENTATION_REFERENCES("DocumentationReferences"),

	ENCAPSULATED_CRL_VALUE("EncapsulatedCRLValue"),

	ENCAPSULATED_OCSP_VALUE("EncapsulatedOCSPValue"),

	ENCAPSULATED_PKI_DATA("EncapsulatedPKIData"),

	ENCAPSULATED_TIMESTAMP("EncapsulatedTimeStamp"),

	ENCAPSULATED_X509_CERTIFICATE("EncapsulatedX509Certificate"),

	ENCODING("Encoding"),

	EXPLICIT_TEXT("ExplicitText"),

	IDENTIFIER("Identifier"),

	INCLUDE("Include"),

	INDIVIDUAL_DATA_OBJECTS_TIMESTAMP("IndividualDataObjectsTimeStamp"),

	INT("int"),

	ISSUE_TIME("IssueTime"),

	ISSUER("Issuer"),

	ISSUER_SERIAL("IssuerSerial"),

	ISSUER_SERIAL_V2("IssuerSerialV2"),
	
	MIME_TYPE("MimeType"),
	
	NOTICE_NUMBERS("NoticeNumbers"),

	NOTICE_REF("NoticeRef"),

	NUMBER("Number"),

	OBJECT_IDENTIFIER("ObjectIdentifier"),

	OBJECT_REFERENCE("ObjectReference"),

	OCSP_IDENTIFIER("OCSPIdentifier"),

	OCSP_REF("OCSPRef"),

	OCSP_REFS("OCSPRefs"),

	OCSP_VALUES("OCSPValues"),

	ORGANIZATION("Organization"),

	OTHER_ATTRIBUTE_CERTIFICATE("OtherAttributeCertificate"),

	OTHER_CERTIFICATE("OtherCertificate"),

	OTHER_REF("OtherRef"),

	OTHER_REFS("OtherRefs"),

	OTHER_TIMESTAMP("OtherTimeStamp"),

	OTHER_VALUE("OtherValue"),

	OTHER_VALUES("OtherValues"),

	POSTAL_CODE("PostalCode"),

	PRODUCED_AT("ProducedAt"),

	QUALIFYING_PROPERTIES("QualifyingProperties"),

	QUALIFYING_PROPERTIES_REFERENCE("QualifyingPropertiesReference"),

	REFERENCE_INFO("ReferenceInfo"),

	REFS_ONLY_TIMESTAMP("RefsOnlyTimeStamp"),
	
	RESPONDER_ID("ResponderID"),

	REVOCATION_VALUES("RevocationValues"),

	SIG_AND_REFS_TIMESTAMP("SigAndRefsTimeStamp"),

	SIG_POLICY_HASH("SigPolicyHash"),

	SIG_POLICY_ID("SigPolicyId"),

	SIG_POLICY_QUALIFIER("SigPolicyQualifier"),
	
	SIG_POLICY_QUALIFIERS("SigPolicyQualifiers"),
	
	SIGNATURE_POLICY_ID("SignaturePolicyId"),
	
	SIGNATURE_POLICY_IDENTIFIER("SignaturePolicyIdentifier"),
	
	SIGNATURE_POLICY_IMPLIED("SignaturePolicyImplied"),
	
	SIGNATURE_PRODUCTION_PLACE("SignatureProductionPlace"),
	
	SIGNATURE_PRODUCTION_PLACE_V2("SignatureProductionPlaceV2"),
	
	SIGNATURE_TIMESTAMP("SignatureTimeStamp"),
	
	SIGNED_ASSERTION("SignedAssertion"),
	
	SIGNED_ASSERTIONS("SignedAssertions"),
	
	SIGNED_DATA_OBJECT_PROPERTIES("SignedDataObjectProperties"),
	
	SIGNED_PROPERTIES("SignedProperties"),
	
	SIGNED_SIGNATURE_PROPERTIES("SignedSignatureProperties"),
	
	SIGNER_ROLE("SignerRole"),
		
	SIGNER_ROLE_V2("SignerRoleV2"),
	
	SIGNING_CERTIFICATE("SigningCertificate"),
	
	SIGNING_CERTIFICATE_V2("SigningCertificateV2"),
	
	SIGNING_TIME("SigningTime"),
	
	SP_URI("SPURI"),
	
	SP_USER_NOTICE("SPUserNotice"),
	
	STATE_OR_PROVINCE("StateOrProvince"),
	
	STREET_ADDRESS("StreetAddress"),
	
	UNSIGNED_DATA_OBJECT_PROPERTIES("UnsignedDataObjectProperties"),

	UNSIGNED_DATA_OBJECT_PROPERTY("UnsignedDataObjectProperty"),

	UNSIGNED_PROPERTIES("UnsignedProperties"),

	UNSIGNED_SIGNATURE_PROPERTIES("UnsignedSignatureProperties"),

	X509_ATTRIBUTE_CERTIFICATE("X509AttributeCertificate"),

	XADES_TIMESTAMP("XAdESTimeStamp"),
	
	XML_TIMESTAMP("XMLTimeStamp");

	private final DSSNamespace namespace;
	private final String tagName;

	XAdES132Element(String tagName) {
		this.tagName = tagName;
		this.namespace = DSSNamespaces.XADES_132;
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
