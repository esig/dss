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
package eu.europa.esig.xades.definition;

import eu.europa.esig.dss.xml.common.definition.DSSElement;

/**
 * Defines a XAdES element
 */
public interface XAdESElement extends DSSElement {

	/**
	 * Gets "AllDataObjectsTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementAllDataObjectsTimeStamp();

	/**
	 * Gets "AllSignedDataObjects" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementAllSignedDataObjects();

	/**
	 * Gets "Any" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementAny();

	/**
	 * Gets "ArchiveTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementArchiveTimeStamp();

	/**
	 * Gets "AttrAuthoritiesCertValues" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementAttrAuthoritiesCertValues();

	/**
	 * Gets "AttributeCertificateRefs" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementAttributeCertificateRefs();

	/**
	 * Gets "AttributeRevocationRefs" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementAttributeRevocationRefs();

	/**
	 * Gets "AttributeRevocationValues" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementAttributeRevocationValues();

	/**
	 * Gets "ByKey" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementByKey();

	/**
	 * Gets "ByName" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementByName();

	/**
	 * Gets "Cert" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCert();

	/**
	 * Gets "CertDigest" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCertDigest();

	/**
	 * Gets "CertRefs" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCertRefs();

	/**
	 * Gets "CertificateValues" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCertificateValues();

	/**
	 * Gets "CertifiedRole" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCertifiedRole();

	/**
	 * Gets "CertifiedRoles" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCertifiedRoles();

	/**
	 * Gets "CertifiedRolesV2" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCertifiedRolesV2();

	/**
	 * Gets "City" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCity();

	/**
	 * Gets "ClaimedRole" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementClaimedRole();

	/**
	 * Gets "ClaimedRoles" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementClaimedRoles();

	/**
	 * Gets "CommitmentTypeId" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCommitmentTypeId();

	/**
	 * Gets "CommitmentTypeIndication" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCommitmentTypeIndication();

	/**
	 * Gets "CommitmentTypeQualifier" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCommitmentTypeQualifier();

	/**
	 * Gets "CommitmentTypeQualifies" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCommitmentTypeQualifiers();

	/**
	 * Gets "CompleteCertificateRefs" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCompleteCertificateRefs();

	/**
	 * Gets "CompleteRevocationRefs" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCompleteRevocationRefs();

	/**
	 * Gets "CounterSignature" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCounterSignature();

	/**
	 * Gets "CountryName" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCountryName();

	/**
	 * Gets "CRLIdentifier" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCRLIdentifier();

	/**
	 * Gets "CRLRef" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCRLRef();

	/**
	 * Gets "CRLRefs" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCRLRefs();

	/**
	 * Gets "CRLValues" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementCRLValues();

	/**
	 * Gets "DataObjectFormat" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementDataObjectFormat();

	/**
	 * Gets "Description" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementDescription();

	/**
	 * Gets "DigestAlgAndValue" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementDigestAlgAndValue();

	/**
	 * Gets "DocumentationReference" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementDocumentationReference();

	/**
	 * Gets "DocumentationReferences" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementDocumentationReferences();

	/**
	 * Gets "EncapsulatedCRLValue" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementEncapsulatedCRLValue();

	/**
	 * Gets "EncapsulatedOCSPValue" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementEncapsulatedOCSPValue();

	/**
	 * Gets "EncapsulatedPKIData" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementEncapsulatedPKIData();

	/**
	 * Gets "EncapsulatedTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementEncapsulatedTimeStamp();

	/**
	 * Gets "EncapsulatedX509Certificate" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementEncapsulatedX509Certificate();

	/**
	 * Gets "Encoding" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementEncoding();

	/**
	 * Gets "ExplicitText" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementExplicitText();

	/**
	 * Gets "Identifier" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementIdentifier();

	/**
	 * Gets "Include" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementInclude();

	/**
	 * Gets "IndividualDataObjectsTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementIndividualDataObjectsTimeStamp();

	/**
	 * Gets "int" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementint();

	/**
	 * Gets "IssueTime" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementIssueTime();

	/**
	 * Gets "IssueTime" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementIssuer();

	/**
	 * Gets "IssuerSerial" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementIssuerSerial();

	/**
	 * Gets "IssuerSerialV2" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementIssuerSerialV2();

	/**
	 * Gets "MimeType" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementMimeType();

	/**
	 * Gets "NoticeNumbers" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementNoticeNumbers();

	/**
	 * Gets "NoticeRef" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementNoticeRef();

	/**
	 * Gets "Number" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementNumber();

	/**
	 * Gets "ObjectIdentifier" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementObjectIdentifier();

	/**
	 * Gets "ObjectReference" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementObjectReference();

	/**
	 * Gets "OCSPIdentifier" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOCSPIdentifier();

	/**
	 * Gets "OCSPRef" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOCSPRef();

	/**
	 * Gets "OCSPRefs" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOCSPRefs();

	/**
	 * Gets "OCSPValues" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOCSPValues();

	/**
	 * Gets "Organization" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOrganization();

	/**
	 * Gets "OtherAttributeCertificate" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOtherAttributeCertificate();

	/**
	 * Gets "OtherCertificate" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOtherCertificate();

	/**
	 * Gets "OtherRef" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOtherRef();

	/**
	 * Gets "OtherRefs" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOtherRefs();

	/**
	 * Gets "OtherTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOtherTimeStamp();

	/**
	 * Gets "OtherValue" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOtherValue();

	/**
	 * Gets "OtherValues" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementOtherValues();

	/**
	 * Gets "PostalCode" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementPostalCode();

	/**
	 * Gets "ProducedAt" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementProducedAt();

	/**
	 * Gets "QualifyingProperties" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementQualifyingProperties();

	/**
	 * Gets "QualifyingPropertiesReference" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementQualifyingPropertiesReference();

	/**
	 * Gets "ReferenceInfo" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementReferenceInfo();

	/**
	 * Gets "RefsOnlyTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementRefsOnlyTimeStamp();

	/**
	 * Gets "ResponderID" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementResponderID();

	/**
	 * Gets "RevocationValues" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementRevocationValues();

	/**
	 * Gets "SigAndRefsTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSigAndRefsTimeStamp();

	/**
	 * Gets "SigPolicyHash" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSigPolicyHash();

	/**
	 * Gets "SigPolicyId" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSigPolicyId();

	/**
	 * Gets "SigPolicyQualifier" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSigPolicyQualifier();

	/**
	 * Gets "SigPolicyQualifiers" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSigPolicyQualifiers();

	/**
	 * Gets "SignaturePolicyId" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignaturePolicyId();

	/**
	 * Gets "SignaturePolicyIdentifier" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignaturePolicyIdentifier();

	/**
	 * Gets "SignaturePolicyImplied" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignaturePolicyImplied();

	/**
	 * Gets "SignatureProductionPlace" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignatureProductionPlace();

	/**
	 * Gets "SignatureProductionPlaceV2" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignatureProductionPlaceV2();

	/**
	 * Gets "SignatureTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignatureTimeStamp();

	/**
	 * Gets "SignedAssertion" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignedAssertion();

	/**
	 * Gets "SignedAssertions" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignedAssertions();

	/**
	 * Gets "SignedDataObjectProperties" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignedDataObjectProperties();

	/**
	 * Gets "SignedProperties" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignedProperties();

	/**
	 * Gets "SignedSignatureProperties" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignedSignatureProperties();

	/**
	 * Gets "SignerRole" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignerRole();

	/**
	 * Gets "SignerRoleV2" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSignerRoleV2();

	/**
	 * Gets "SigningCertificate" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSigningCertificate();

	/**
	 * Gets "SigningCertificateV2" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSigningCertificateV2();

	/**
	 * Gets "SigningTime" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSigningTime();

	/**
	 * Gets "SPURI" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSPURI();

	/**
	 * Gets "SPUserNotice" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementSPUserNotice();

	/**
	 * Gets "StateOrProvince" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementStateOrProvince();

	/**
	 * Gets "StreetAddress" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementStreetAddress();

	/**
	 * Gets "UnsignedDataObjectProperties" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementUnsignedDataObjectProperties();

	/**
	 * Gets "UnsignedDataObjectProperty" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementUnsignedDataObjectProperty();

	/**
	 * Gets "UnsignedProperties" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementUnsignedProperties();

	/**
	 * Gets "UnsignedSignatureProperties" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementUnsignedSignatureProperties();

	/**
	 * Gets "X509AttributeCertificate" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementX509AttributeCertificate();

	/**
	 * Gets "XAdESTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementXAdESTimeStamp();

	/**
	 * Gets "XMLTimeStamp" element
	 *
	 * @return {@link DSSElement}
	 */
	DSSElement getElementXMLTimeStamp();

}
