/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.definition;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;

import java.io.Serializable;

/**
 * Contains a list of useful XAdES XPaths
 */
public interface XAdESPath extends Serializable {

	/**
	 * Gets the current namespace
	 *
	 * @return {@link DSSNamespace}
	 */
	DSSNamespace getNamespace();

	/**
	 * Gets signed properties reference URI
	 *
	 * @return {@link String}
	 */
	String getSignedPropertiesUri();

	/**
	 * Gets counter signature reference URI
	 *
	 * @return {@link String}
	 */
	String getCounterSignatureUri();

	// ----------------------- From Object

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getQualifyingPropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignedPropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignedSignaturePropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSigningTimePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSigningCertificatePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSigningCertificateChildren();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificateV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSigningCertificateV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificateV2/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSigningCertificateV2Children();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignatureProductionPlace"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignatureProductionPlacePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignatureProductionPlaceV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignatureProductionPlaceV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignaturePolicyIdentifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignaturePolicyIdentifierPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRole"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignerRolePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getClaimedRolePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRole/xades:SignedAssertions/xades:SignedAssertion"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignedAssertionPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRoleV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignerRoleV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRoleV2/xades:ClaimedRoles/xades:ClaimedRole"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getClaimedRoleV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRole/xades:CertifiedRoles/xades:CertifiedRole"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCertifiedRolePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SignerRoleV2/xades:CertifiedRoles/xades:CertifiedRole"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCertifiedRoleV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignedDataObjectPropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:AllDataObjectsTimeStamp"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAllDataObjectsTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:IndividualDataObjectsTimeStamp"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getIndividualDataObjectsTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getDataObjectFormat();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat/xades:MimeType"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getDataObjectFormatMimeType();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:DataObjectFormat/xades:ObjectIdentifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getDataObjectFormatObjectIdentifier();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:CommitmentTypeIndication"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCommitmentTypeIndicationPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getUnsignedPropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getUnsignedSignaturePropertiesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CounterSignature"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCounterSignaturePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttributeRevocationRefs"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAttributeRevocationRefsPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCompleteRevocationRefsPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCompleteCertificateRefsPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs/xades:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCompleteCertificateRefsCertPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:CompleteCertificateRefsV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCompleteCertificateRefsV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:CompleteCertificateRefsV2/xades141:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCompleteCertificateRefsV2CertPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttributeCertificateRefs"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAttributeCertificateRefsPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttributeCertificateRefs/xades:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAttributeCertificateRefsCertPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:AttributeCertificateRefsV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAttributeCertificateRefsV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:AttributeCertificateRefsV2/xades141:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAttributeCertificateRefsV2CertPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CertificateValues"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCertificateValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:RevocationValues"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getRevocationValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttributeRevocationValues"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAttributeRevocationValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:SigAndRefsTimeStampV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getEncapsulatedCertificateValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttrAuthoritiesCertValues"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAttrAuthoritiesCertValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:AttrAuthoritiesCertValues/xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getEncapsulatedAttrAuthoritiesCertValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:TimeStampValidationData/xades:CertificateValues/xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getEncapsulatedTimeStampValidationDataCertValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:TimeStampValidationData/xades:RevocationValues"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getTimeStampValidationDataRevocationValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:AnyValidationData"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAnyValidationDataPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:AnyValidationData/xades:CertificateValues/xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getEncapsulatedAnyValidationDataCertValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:AnyValidationData/xades:RevocationValues"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getAnyValidationDataRevocationValuesPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignatureTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SigAndRefsTimeStamp"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSigAndRefsTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:SigAndRefsTimeStampV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSigAndRefsTimestampV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:RefsOnlyTimeStamp"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getRefsOnlyTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:RefsOnlyTimeStampV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getRefsOnlyTimestampV2Path();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getArchiveTimestampPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:TimeStampValidationData"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getTimestampValidationDataPath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades141:SignaturePolicyStore"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSignaturePolicyStorePath();

	/**
	 * Gets path "./ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xadesen:SealingEvidenceRecords"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getSealingEvidenceRecordsPath();

	// ----------------

	/**
	 * Gets path "./xades:CRLValues/xades:EncapsulatedCRLValue"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCRLValuesChildren();

	/**
	 * Gets path "./xades:CRLRefs/xades:CRLRef"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCRLRefsChildren();

	/**
	 * Gets path "./xades:CRLIdentifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCRLRefCRLIdentifier();

	/**
	 * Gets path "./xades:CRLIdentifier/xades:Issuer"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCRLRefCRLIdentifierIssuer();

	/**
	 * Gets path "./xades:CRLIdentifier/xades:IssueTime"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCRLRefCRLIdentifierIssueTime();

	/**
	 * Gets path "./xades:CRLIdentifier/xades:Number"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCRLRefCRLIdentifierNumber();

	/**
	 * Gets path "./xades:OCSPValues/xades:EncapsulatedOCSPValue"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentOCSPValuesChildren();

	/**
	 * Gets path "./xades:OCSPRefs/xades:OCSPRef"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentOCSPRefsChildren();

	/**
	 * Gets path "./xades:OCSPIdentifier/xades:ResponderID"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentOCSPRefResponderID();

	/**
	 * Gets path "./xades:OCSPIdentifier/xades:ResponderID/xades:ByName"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentOCSPRefResponderIDByName();

	/**
	 * Gets path "./xades:OCSPIdentifier/xades:ResponderID/xades:ByKey"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentOCSPRefResponderIDByKey();

	/**
	 * Gets path "./xades:OCSPIdentifier/xades:ProducedAt"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentOCSPRefProducedAt();

	/**
	 * Gets path "./xades:DigestAlgAndValue"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentDigestAlgAndValue();

	/**
	 * Gets path "./xades:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCertRefsCertChildren();

	/**
	 * Gets path "./xades141:CertRefs/xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCertRefs141CertChildren();

	/**
	 * Gets path "./xades:Cert"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCertChildren();

	/**
	 * Gets path "./xades:CertDigest"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCertDigest();

	/**
	 * Gets path "./xades:EncapsulatedTimeStamp"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentEncapsulatedTimestamp();

	/**
	 * Gets path "./xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentEncapsulatedCertificate();

	/**
	 * Gets path "./xades:CertificateValues/xades:EncapsulatedX509Certificate"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCertificateValuesEncapsulatedCertificate();

	/**
	 * Gets path "./xades:RevocationValues/xades:OCSPValues/xades:EncapsulatedOCSPValue"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentRevocationValuesEncapsulatedOCSPValue();

	/**
	 * Gets path "./xades:OCSPValues/xades:EncapsulatedOCSPValue"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentEncapsulatedOCSPValue();

	/**
	 * Gets path "./xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentRevocationValuesEncapsulatedCRLValue();

	/**
	 * Gets path "./xades:CRLValues/xades:EncapsulatedCRLValue"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentEncapsulatedCRLValue();

	/**
	 * Gets path "./xades:IssuerSerial/xades:X509IssuerName"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentIssuerSerialIssuerNamePath();

	/**
	 * Gets path "./xades:IssuerSerial/xades:X509SerialNumber"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentIssuerSerialSerialNumberPath();

	/**
	 * Gets path "./xades:IssuerSerialV2"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentIssuerSerialV2Path();

	/**
	 * Gets path "./xades:CommitmentTypeId/xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCommitmentIdentifierPath();

	/**
	 * Gets path "./xades:CommitmentTypeId/xades:Description"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCommitmentDescriptionPath();

	/**
	 * Gets path "./xades:CommitmentTypeId/xades:DocumentationReferences"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCommitmentDocumentationReferencesPath();

	/**
	 * Gets path "./xades:DocumentationReferences"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentDocumentationReference();

	/**
	 * Gets path "./xades:Description"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentDescription();

	/**
	 * Gets path "./xades:ObjectIdentifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentObjectIdentifier();

	/**
	 * Gets path "./xades:ObjectReference"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCommitmentObjectReferencesPath();

	/**
	 * Gets path "./xades:AllSignedDataObjects"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentCommitmentAllSignedDataObjectsPath();

	/**
	 * Gets path "./xades:MimeType"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentMimeType();

	/**
	 * Gets path "./xades:Encoding"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentEncoding();

	// --------------------------- Policy

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicyId();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyHash"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicyDigestAlgAndValue();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades:SPURI"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicySPURI();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades:SPUserNotice"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicySPUserNotice();

	/**
	 * Gets path "./xades:NoticeRef/xades:Organization"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSPUserNoticeNoticeRefOrganization();

	/**
	 * Gets path "./xades:NoticeRef/xades:NoticeNumbers"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSPUserNoticeNoticeRefNoticeNumbers();

	/**
	 * Gets path "./xades:NoticeRef/xades:NoticeNumbers"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSPUserNoticeExplicitText();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades141:SPDocSpecification"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicySPDocSpecification();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyQualifiers/xades:SigPolicyQualifier/xades141:SPDocSpecification/xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicySPDocSpecificationIdentifier();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Description"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicyDescription();

	/**
	 * Gets path "./xades:SignaturePolicyId/xades:SigPolicyId/xades:DocumentationReferences"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicyDocumentationReferences();

	/**
	 * Gets path "./xades:SignaturePolicyImplied"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicyImplied();

	/**
	 * Gets path "./xades:SignaturePolicyId/ds:Transforms"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicyTransforms();

	/**
	 * Gets path "./xades:SignaturePolicyId/ds:SigPolicyQualifiers"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicyQualifiers();

	/**
	 * Gets path "./xades:Include"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentInclude();

	/**
	 * Gets path "./xades:QualifyingProperties"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentQualifyingPropertiesPath();

	// --------------------------- Signature Policy Store

	/**
	 * Gets path "./xades141:SPDocSpecification"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSPDocSpecification();

	/**
	 * Gets path "./xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentIdentifier();

	/**
	 * Gets path "./xades141:SPDocSpecification/xades:Identifier"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSPDocSpecificationIdentifier();

	/**
	 * Gets path "./xades141:SPDocSpecification/xades:Description"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSPDocSpecificationDescription();

	/**
	 * Gets path ".xades:DocumentationReferences/xades:DocumentationReference"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentDocumentationReferenceElements();

	/**
	 * Gets path "./xades141:SPDocSpecification/xades:DocumentationReferences/xades:DocumentationReference"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSPDocSpecificationDocumentationReferenceElements();

	/**
	 * Gets path "./xades141:SignaturePolicyDocument"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSignaturePolicyDocument();

	/**
	 * Gets path "./xades141:SigPolDocLocalURI"
	 *
	 * @return {@link String} path
	 */
	XPathQuery getCurrentSigPolDocLocalURI();

}
