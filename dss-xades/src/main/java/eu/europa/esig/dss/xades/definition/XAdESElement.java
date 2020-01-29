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
package eu.europa.esig.dss.xades.definition;

import eu.europa.esig.dss.definition.DSSElement;

public interface XAdESElement extends DSSElement {

	DSSElement getElementAllDataObjectsTimeStamp();

	DSSElement getElementAllSignedDataObjects();

	DSSElement getElementAny();

	DSSElement getElementArchiveTimeStamp();

	DSSElement getElementAttrAuthoritiesCertValues();

	DSSElement getElementAttributeCertificateRefs();

	DSSElement getElementAttributeRevocationRefs();

	DSSElement getElementAttributeRevocationValues();

	DSSElement getElementByKey();

	DSSElement getElementByName();

	DSSElement getElementCert();

	DSSElement getElementCertDigest();

	DSSElement getElementCertRefs();

	DSSElement getElementCertificateValues();

	DSSElement getElementCertifiedRole();

	DSSElement getElementCertifiedRoles();

	DSSElement getElementCertifiedRolesV2();

	DSSElement getElementCity();

	DSSElement getElementClaimedRole();

	DSSElement getElementClaimedRoles();

	DSSElement getElementCommitmentTypeId();

	DSSElement getElementCommitmentTypeIndication();

	DSSElement getElementCommitmentTypeQualifier();

	DSSElement getElementCommitmentTypeQualifiers();

	DSSElement getElementCompleteCertificateRefs();

	DSSElement getElementCompleteRevocationRefs();

	DSSElement getElementCounterSignature();

	DSSElement getElementCountryName();

	DSSElement getElementCRLIdentifier();

	DSSElement getElementCRLRef();

	DSSElement getElementCRLRefs();

	DSSElement getElementCRLValues();

	DSSElement getElementDataObjectFormat();

	DSSElement getElementDescription();

	DSSElement getElementDigestAlgAndValue();

	DSSElement getElementDocumentationReference();

	DSSElement getElementDocumentationReferences();

	DSSElement getElementEncapsulatedCRLValue();

	DSSElement getElementEncapsulatedOCSPValue();

	DSSElement getElementEncapsulatedPKIData();

	DSSElement getElementEncapsulatedTimeStamp();

	DSSElement getElementEncapsulatedX509Certificate();

	DSSElement getElementEncoding();

	DSSElement getElementExplicitText();

	DSSElement getElementIdentifier();

	DSSElement getElementInclude();

	DSSElement getElementIndividualDataObjectsTimeStamp();

	DSSElement getElementint();

	DSSElement getElementIssueTime();

	DSSElement getElementIssuer();

	DSSElement getElementIssuerSerial();

	DSSElement getElementIssuerSerialV2();

	DSSElement getElementMimeType();

	DSSElement getElementNoticeNumbers();

	DSSElement getElementNoticeRef();

	DSSElement getElementNumber();

	DSSElement getElementObjectIdentifier();

	DSSElement getElementObjectReference();

	DSSElement getElementOCSPIdentifier();

	DSSElement getElementOCSPRef();

	DSSElement getElementOCSPRefs();

	DSSElement getElementOCSPValues();

	DSSElement getElementOrganization();

	DSSElement getElementOtherAttributeCertificate();

	DSSElement getElementOtherCertificate();

	DSSElement getElementOtherRef();

	DSSElement getElementOtherRefs();

	DSSElement getElementOtherTimeStamp();

	DSSElement getElementOtherValue();

	DSSElement getElementOtherValues();

	DSSElement getElementPostalCode();

	DSSElement getElementProducedAt();

	DSSElement getElementQualifyingProperties();

	DSSElement getElementQualifyingPropertiesReference();

	DSSElement getElementReferenceInfo();

	DSSElement getElementRefsOnlyTimeStamp();

	DSSElement getElementResponderID();

	DSSElement getElementRevocationValues();

	DSSElement getElementSigAndRefsTimeStamp();

	DSSElement getElementSigPolicyHash();

	DSSElement getElementSigPolicyId();

	DSSElement getElementSigPolicyQualifier();

	DSSElement getElementSigPolicyQualifiers();

	DSSElement getElementSignaturePolicyId();

	DSSElement getElementSignaturePolicyIdentifier();

	DSSElement getElementSignaturePolicyImplied();

	DSSElement getElementSignatureProductionPlace();

	DSSElement getElementSignatureProductionPlaceV2();

	DSSElement getElementSignatureTimeStamp();

	DSSElement getElementSignedAssertion();

	DSSElement getElementSignedAssertions();

	DSSElement getElementSignedDataObjectProperties();

	DSSElement getElementSignedProperties();

	DSSElement getElementSignedSignatureProperties();

	DSSElement getElementSignerRole();

	DSSElement getElementSignerRoleV2();

	DSSElement getElementSigningCertificate();

	DSSElement getElementSigningCertificateV2();

	DSSElement getElementSigningTime();

	DSSElement getElementSPURI();

	DSSElement getElementSPUserNotice();

	DSSElement getElementStateOrProvince();

	DSSElement getElementStreetAddress();

	DSSElement getElementUnsignedDataObjectProperties();

	DSSElement getElementUnsignedDataObjectProperty();

	DSSElement getElementUnsignedProperties();

	DSSElement getElementUnsignedSignatureProperties();

	DSSElement getElementX509AttributeCertificate();

	DSSElement getElementXAdESTimeStamp();

	DSSElement getElementXMLTimeStamp();

}
