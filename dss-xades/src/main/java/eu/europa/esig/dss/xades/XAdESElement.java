package eu.europa.esig.dss.xades;

public enum XAdESElement implements DSSElement {

	ANY("Any"),

	IDENTIFIER("Identifier"),

	DOCUMENTATION_REFERENCES("DocumentationReferences"),

	DOCUMENTATION_REFERENCE("DocumentationReference"),

	ENCAPSULATED_PKI_DATA("EncapsulatedPKIData"),

	INCLUDE("Include"),

	REFERENCE_INFO("ReferenceInfo"),

	XADES_TIMESTAMP("XAdESTimeStamp"),

	OTHER_TIMESTAMP("OtherTimeStamp"),

	ENCAPSULATED_TIMESTAMP("EncapsulatedTimeStamp"),

	XML_TIMESTAMP("XMLTimeStamp"),

	QUALIFYING_PROPERTIES("QualifyingProperties"),

	SIGNED_PROPERTIES("SignedProperties"),

	UNSIGNED_PROPERTIES("UnsignedProperties"),

	SIGNED_SIGNATURE_PROPERTIES("SignedSignatureProperties"),

	SIGNED_DATA_OBJECT_PROPERTIES("SignedDataObjectProperties"),

	UNSIGNED_SIGNATURE_PROPERTIES("UnsignedSignatureProperties"),

	UNSIGNED_DATA_OBJECT_PROPERTIES("UnsignedDataObjectProperties"),

	UNSIGNED_DATA_OBJECT_PROPERTY("UnsignedDataObjectProperty"),

	QUALIFYING_PROPERTIES_REFERENCE("QualifyingPropertiesReference"),

	SIGNING_TIME("SigningTime"),

	SIGNING_CERTIFICATE("SigningCertificate"),

	SIGNING_CERTIFICATE_V2("SigningCertificateV2"),

	CERT("Cert"),

	CERT_DIGEST("CertDigest"),

	ISSUER_SERIAL("IssuerSerial"),

	ISSUER_SERIAL_V2("IssuerSerialV2"),

	SIGNATURE_POLICY_IDENTIFIER("SignaturePolicyIdentifier"),

	SIGNATURE_POLICY_ID("SignaturePolicyId"),

	SIGNATURE_POLICY_IMPLIED("SignaturePolicyImplied"),

	SIG_POLICY_ID("SigPolicyId"),

	SIG_POLICY_HASH("SigPolicyHash"),

	SIG_POLICY_QUALIFIERS("SigPolicyQualifiers"),

	SIG_POLICY_QUALIFIER("SigPolicyQualifier"),

	SP_URI("SPURI"),

	SP_USER_NOTICE("SPUserNotice"),

	NOTICE_REF("NoticeRef"),

	EXPLICIT_TEXT("ExplicitText"),

	ORGANIZATION("Organization"),

	NOTICE_NUMBERS("NoticeNumbers"),

	COUNTER_SIGNATURE("CounterSignature"),

	DATA_OBJECT_FORMAT("DataObjectFormat"),

	DESCRIPTION("Description"),

	OBJECT_IDENTIFIER("ObjectIdentifier"),

	MIME_TYPE("MimeType"),

	ENCODING("Encoding"),

	COMMITMENT_TYPE_INDICATION("CommitmentTypeIndication"),

	COMMITMENT_TYPE_ID("CommitmentTypeId"),

	OBJECT_REFERENCE("ObjectReference"),

	ALL_SIGNED_DATA_OBJECTS("AllSignedDataObjects"),

	COMMITMENT_TYPE_QUALIFIERS("CommitmentTypeQualifiers"),

	COMMITMENT_TYPE_QUALIFIER("CommitmentTypeQualifier"),
	
	SIGNATURE_PRODUCTION_PLACE("SignatureProductionPlace"),
	
	SIGNATURE_PRODUCTION_PLACE_V2("SignatureProductionPlaceV2"),

	CITY("City"),

	STREET_ADDRESS("StreetAddress"),

	STATE_OR_PROVINCE("StateOrProvince"),

	POSTAL_CODE("PostalCode"),

	COUNTRY_NAME("CountryName"),

	SIGNER_ROLE("SignerRole"),

	SIGNER_ROLE_V2("SignerRoleV2"),

	CLAIMED_ROLES("ClaimedRoles"),

	CERTIFIED_ROLES("CertifiedRoles"),

	CERTIFIED_ROLES_V2("CertifiedRolesV2"),

	X509_ATTRIBUTE_CERTIFICATE("X509AttributeCertificate"),

	OTHER_ATTRIBUTE_CERTIFICATE("OtherAttributeCertificate"),

	SIGNED_ASSERTIONS("SignedAssertions"),

	SIGNED_ASSERTION("SignedAssertion"),

	CLAIMED_ROLE("ClaimedRole"),

	CERTIFIED_ROLE("CertifiedRole"),

	ALL_DATA_OBJECTS_TIMESTAMP("AllDataObjectsTimeStamp"),

	INDIVIDUAL_DATA_OBJECTS_TIMESTAMP("IndividualDataObjectsTimeStamp"),

	SIGNATURE_TIMESTAMP("SignatureTimeStamp"),

	COMPLETE_CERTIFICATE_REFS("CompleteCertificateRefs"),

	CERT_REFS("CertRefs"),

	COMPLETE_REVOCATION_REFS("CompleteRevocationRefs"),
	
	CRL_REFS("CRLRefs"),

	OCSP_REFS("OCSPRefs"),

	OTHER_REFS("OtherRefs"),

	CRL_REF("CRLRef"),

	CRL_IDENTIFIER("CRLIdentifier"),

	ISSUER("Issuer"),
	
	ISSUE_TIME("IssueTime"),
	
	NUMBER("Number"),
	
	OCSP_REF("OCSPRef"),
	
	OCSP_IDENTIFIER("OCSPIdentifier"),
	
	DIGEST_ALG_AND_VALUE("DigestAlgAndValue"),
	
	BY_NAME("ByName"),
	
	BY_KEY("ByKey"),
	
	RESPONDER_ID("ResponderID"),
	
	PRODUCED_AT("ProducedAt"),
	
	OTHER_REF("OtherRef"),
	
	ATTRIBUTE_CERTIFICATE_REFS("AttributeCertificateRefs"),
	
	ATTRIBUTE_REVOCATION_REFS("AttributeRevocationRefs"),
	
	SIG_AND_REFS_TIMESTAMP("SigAndRefsTimeStamp"),
		
	REFS_ONLY_TIMESTAMP("RefsOnlyTimeStamp"),
	
	CERTIFICATE_VALUES("CertificateValues"),
	
	ENCAPSULATED_X509_CERTIFICATE("EncapsulatedX509Certificate"),
	
	OTHER_CERTIFICATE("OtherCertificate"),
	
	REVOCATION_VALUES("RevocationValues"),
	
	CRL_VALUES("CRLValues"),
	
	OCSP_VALUES("OCSPValues"),
	
	OTHER_VALUES("OtherValues"),
	
	ENCAPSULATED_CRL_VALUE("EncapsulatedCRLValue"),

	ENCAPSULATED_OCSP_VALUE("EncapsulatedOCSPValue"),

	OTHER_VALUE("OtherValue"),

	ATTR_AUTHORITIES_CERT_VALUES("AttrAuthoritiesCertValues"),

	ATTRIBUTE_REVOCATION_VALUES("AttributeRevocationValues"),

	ARCHIVE_TIMESTAMP("ArchiveTimeStamp");

	private final String tagName;
	private final DSSNamespace namespace;

	XAdESElement(String tagName) {
		this.tagName = tagName;
		this.namespace = DSSNamespaces.XADES;
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
