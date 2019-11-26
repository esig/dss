/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.definition.xades132;

import eu.europa.esig.dss.definition.DSSElement;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.xades.definition.XAdESElement;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;

public enum XAdES132Element implements XAdESElement {

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
		this.namespace = XAdESNamespaces.XADES_132;
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

	public static DSSElement fromTagName(String tagName) {
		for (XAdES132Element element : XAdES132Element.values()) {
			if (element.getTagName().equals(tagName)) {
				return element;
			}
		}
		return null;
	}

	@Override
	public DSSElement getElementAllDataObjectsTimeStamp() {
		return ALL_DATA_OBJECTS_TIMESTAMP;
	}

	@Override
	public DSSElement getElementAllSignedDataObjects() {
		return ALL_SIGNED_DATA_OBJECTS;
	}

	@Override
	public DSSElement getElementAny() {
		return ANY;
	}

	@Override
	public DSSElement getElementArchiveTimeStamp() {
		return ARCHIVE_TIMESTAMP;
	}

	@Override
	public DSSElement getElementAttrAuthoritiesCertValues() {
		return ATTR_AUTHORITIES_CERT_VALUES;
	}

	@Override
	public DSSElement getElementAttributeCertificateRefs() {
		return ATTRIBUTE_CERTIFICATE_REFS;
	}

	@Override
	public DSSElement getElementAttributeRevocationRefs() {
		return ATTRIBUTE_REVOCATION_REFS;
	}

	@Override
	public DSSElement getElementAttributeRevocationValues() {
		return ATTRIBUTE_REVOCATION_VALUES;
	}

	@Override
	public DSSElement getElementByKey() {
		return BY_KEY;
	}

	@Override
	public DSSElement getElementByName() {
		return BY_NAME;
	}

	@Override
	public DSSElement getElementCert() {
		return CERT;
	}

	@Override
	public DSSElement getElementCertDigest() {
		return CERT_DIGEST;
	}

	@Override
	public DSSElement getElementCertRefs() {
		return CERT_REFS;
	}

	@Override
	public DSSElement getElementCertificateValues() {
		return CERTIFICATE_VALUES;
	}

	@Override
	public DSSElement getElementCertifiedRole() {
		return CERTIFIED_ROLE;
	}

	@Override
	public DSSElement getElementCertifiedRoles() {
		return CERTIFIED_ROLES;
	}

	@Override
	public DSSElement getElementCertifiedRolesV2() {
		return CERTIFIED_ROLES_V2;
	}

	@Override
	public DSSElement getElementCity() {
		return CITY;
	}

	@Override
	public DSSElement getElementClaimedRole() {
		return CLAIMED_ROLE;
	}

	@Override
	public DSSElement getElementClaimedRoles() {
		return CLAIMED_ROLES;
	}

	@Override
	public DSSElement getElementCommitmentTypeId() {
		return COMMITMENT_TYPE_ID;
	}

	@Override
	public DSSElement getElementCommitmentTypeIndication() {
		return COMMITMENT_TYPE_INDICATION;
	}

	@Override
	public DSSElement getElementCommitmentTypeQualifier() {
		return COMMITMENT_TYPE_QUALIFIER;
	}

	@Override
	public DSSElement getElementCommitmentTypeQualifiers() {
		return COMMITMENT_TYPE_QUALIFIERS;
	}

	@Override
	public DSSElement getElementCompleteCertificateRefs() {
		return COMPLETE_CERTIFICATE_REFS;
	}

	@Override
	public DSSElement getElementCompleteRevocationRefs() {
		return COMPLETE_REVOCATION_REFS;
	}

	@Override
	public DSSElement getElementCounterSignature() {
		return COUNTER_SIGNATURE;
	}

	@Override
	public DSSElement getElementCountryName() {
		return COUNTRY_NAME;
	}

	@Override
	public DSSElement getElementCRLIdentifier() {
		return CRL_IDENTIFIER;
	}

	@Override
	public DSSElement getElementCRLRef() {
		return CRL_REF;
	}

	@Override
	public DSSElement getElementCRLRefs() {
		return CRL_REFS;
	}

	@Override
	public DSSElement getElementCRLValues() {
		return CRL_VALUES;
	}

	@Override
	public DSSElement getElementDataObjectFormat() {
		return DATA_OBJECT_FORMAT;
	}

	@Override
	public DSSElement getElementDescription() {
		return DESCRIPTION;
	}

	@Override
	public DSSElement getElementDigestAlgAndValue() {
		return DIGEST_ALG_AND_VALUE;
	}

	@Override
	public DSSElement getElementDocumentationReference() {
		return DOCUMENTATION_REFERENCE;
	}

	@Override
	public DSSElement getElementDocumentationReferences() {
		return DOCUMENTATION_REFERENCES;
	}

	@Override
	public DSSElement getElementEncapsulatedCRLValue() {
		return ENCAPSULATED_CRL_VALUE;
	}

	@Override
	public DSSElement getElementEncapsulatedOCSPValue() {
		return ENCAPSULATED_OCSP_VALUE;
	}

	@Override
	public DSSElement getElementEncapsulatedPKIData() {
		return ENCAPSULATED_PKI_DATA;
	}

	@Override
	public DSSElement getElementEncapsulatedTimeStamp() {
		return ENCAPSULATED_TIMESTAMP;
	}

	@Override
	public DSSElement getElementEncapsulatedX509Certificate() {
		return ENCAPSULATED_X509_CERTIFICATE;
	}

	@Override
	public DSSElement getElementEncoding() {
		return ENCODING;
	}

	@Override
	public DSSElement getElementExplicitText() {
		return EXPLICIT_TEXT;
	}

	@Override
	public DSSElement getElementIdentifier() {
		return IDENTIFIER;
	}

	@Override
	public DSSElement getElementInclude() {
		return INCLUDE;
	}

	@Override
	public DSSElement getElementIndividualDataObjectsTimeStamp() {
		return INDIVIDUAL_DATA_OBJECTS_TIMESTAMP;
	}

	@Override
	public DSSElement getElementint() {
		return INT;
	}

	@Override
	public DSSElement getElementIssueTime() {
		return ISSUE_TIME;
	}

	@Override
	public DSSElement getElementIssuer() {
		return ISSUER;
	}

	@Override
	public DSSElement getElementIssuerSerial() {
		return ISSUER_SERIAL;
	}

	@Override
	public DSSElement getElementIssuerSerialV2() {
		return ISSUER_SERIAL_V2;
	}

	@Override
	public DSSElement getElementMimeType() {
		return MIME_TYPE;
	}

	@Override
	public DSSElement getElementNoticeNumbers() {
		return NOTICE_NUMBERS;
	}

	@Override
	public DSSElement getElementNoticeRef() {
		return NOTICE_REF;
	}

	@Override
	public DSSElement getElementNumber() {
		return NUMBER;
	}

	@Override
	public DSSElement getElementObjectIdentifier() {
		return OBJECT_IDENTIFIER;
	}

	@Override
	public DSSElement getElementObjectReference() {
		return OBJECT_REFERENCE;
	}

	@Override
	public DSSElement getElementOCSPIdentifier() {
		return OCSP_IDENTIFIER;
	}

	@Override
	public DSSElement getElementOCSPRef() {
		return OCSP_REF;
	}

	@Override
	public DSSElement getElementOCSPRefs() {
		return OCSP_REFS;
	}

	@Override
	public DSSElement getElementOCSPValues() {
		return OCSP_VALUES;
	}

	@Override
	public DSSElement getElementOrganization() {
		return ORGANIZATION;
	}

	@Override
	public DSSElement getElementOtherAttributeCertificate() {
		return OTHER_ATTRIBUTE_CERTIFICATE;
	}

	@Override
	public DSSElement getElementOtherCertificate() {
		return OTHER_CERTIFICATE;
	}

	@Override
	public DSSElement getElementOtherRef() {
		return OTHER_REF;
	}

	@Override
	public DSSElement getElementOtherRefs() {
		return OTHER_REFS;
	}

	@Override
	public DSSElement getElementOtherTimeStamp() {
		return OTHER_TIMESTAMP;
	}

	@Override
	public DSSElement getElementOtherValue() {
		return OTHER_VALUE;
	}

	@Override
	public DSSElement getElementOtherValues() {
		return OTHER_VALUES;
	}

	@Override
	public DSSElement getElementPostalCode() {
		return POSTAL_CODE;
	}

	@Override
	public DSSElement getElementProducedAt() {
		return PRODUCED_AT;
	}

	@Override
	public DSSElement getElementQualifyingProperties() {
		return QUALIFYING_PROPERTIES;
	}

	@Override
	public DSSElement getElementQualifyingPropertiesReference() {
		return QUALIFYING_PROPERTIES_REFERENCE;
	}

	@Override
	public DSSElement getElementReferenceInfo() {
		return REFERENCE_INFO;
	}

	@Override
	public DSSElement getElementRefsOnlyTimeStamp() {
		return REFS_ONLY_TIMESTAMP;
	}

	@Override
	public DSSElement getElementResponderID() {
		return RESPONDER_ID;
	}

	@Override
	public DSSElement getElementRevocationValues() {
		return REVOCATION_VALUES;
	}

	@Override
	public DSSElement getElementSigAndRefsTimeStamp() {
		return SIG_AND_REFS_TIMESTAMP;
	}

	@Override
	public DSSElement getElementSigPolicyHash() {
		return SIG_POLICY_HASH;
	}

	@Override
	public DSSElement getElementSigPolicyId() {
		return SIG_POLICY_ID;
	}

	@Override
	public DSSElement getElementSigPolicyQualifier() {
		return SIG_POLICY_QUALIFIER;
	}

	@Override
	public DSSElement getElementSigPolicyQualifiers() {
		return SIG_POLICY_QUALIFIERS;
	}

	@Override
	public DSSElement getElementSignaturePolicyId() {
		return SIGNATURE_POLICY_ID;
	}

	@Override
	public DSSElement getElementSignaturePolicyIdentifier() {
		return SIGNATURE_POLICY_IDENTIFIER;
	}

	@Override
	public DSSElement getElementSignaturePolicyImplied() {
		return SIGNATURE_POLICY_IMPLIED;
	}

	@Override
	public DSSElement getElementSignatureProductionPlace() {
		return SIGNATURE_PRODUCTION_PLACE;
	}

	@Override
	public DSSElement getElementSignatureProductionPlaceV2() {
		return SIGNATURE_PRODUCTION_PLACE_V2;
	}

	@Override
	public DSSElement getElementSignatureTimeStamp() {
		return SIGNATURE_TIMESTAMP;
	}

	@Override
	public DSSElement getElementSignedAssertion() {
		return SIGNED_ASSERTION;
	}

	@Override
	public DSSElement getElementSignedAssertions() {
		return SIGNED_ASSERTIONS;
	}

	@Override
	public DSSElement getElementSignedDataObjectProperties() {
		return SIGNED_DATA_OBJECT_PROPERTIES;
	}

	@Override
	public DSSElement getElementSignedProperties() {
		return SIGNED_PROPERTIES;
	}

	@Override
	public DSSElement getElementSignedSignatureProperties() {
		return SIGNED_SIGNATURE_PROPERTIES;
	}

	@Override
	public DSSElement getElementSignerRole() {
		return SIGNER_ROLE;
	}

	@Override
	public DSSElement getElementSignerRoleV2() {
		return SIGNER_ROLE_V2;
	}

	@Override
	public DSSElement getElementSigningCertificate() {
		return SIGNING_CERTIFICATE;
	}

	@Override
	public DSSElement getElementSigningCertificateV2() {
		return SIGNING_CERTIFICATE_V2;
	}

	@Override
	public DSSElement getElementSigningTime() {
		return SIGNING_TIME;
	}

	@Override
	public DSSElement getElementSPURI() {
		return SP_URI;
	}

	@Override
	public DSSElement getElementSPUserNotice() {
		return SP_USER_NOTICE;
	}

	@Override
	public DSSElement getElementStateOrProvince() {
		return STATE_OR_PROVINCE;
	}

	@Override
	public DSSElement getElementStreetAddress() {
		return STREET_ADDRESS;
	}

	@Override
	public DSSElement getElementUnsignedDataObjectProperties() {
		return UNSIGNED_DATA_OBJECT_PROPERTIES;
	}

	@Override
	public DSSElement getElementUnsignedDataObjectProperty() {
		return UNSIGNED_DATA_OBJECT_PROPERTY;
	}

	@Override
	public DSSElement getElementUnsignedProperties() {
		return UNSIGNED_PROPERTIES;
	}

	@Override
	public DSSElement getElementUnsignedSignatureProperties() {
		return UNSIGNED_SIGNATURE_PROPERTIES;
	}

	@Override
	public DSSElement getElementX509AttributeCertificate() {
		return X509_ATTRIBUTE_CERTIFICATE;
	}

	@Override
	public DSSElement getElementXAdESTimeStamp() {
		return XADES_TIMESTAMP;
	}

	@Override
	public DSSElement getElementXMLTimeStamp() {
		return XML_TIMESTAMP;
	}

}
