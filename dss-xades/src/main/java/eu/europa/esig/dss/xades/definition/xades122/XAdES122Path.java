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
package eu.europa.esig.dss.xades.definition.xades122;

import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xml.common.definition.AbstractPath;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;

/**
 * XAdES 1.2.2 paths
 */
public class XAdES122Path extends AbstractPath implements XAdESPath {

	private static final long serialVersionUID = 5349623288353583493L;

	/**
	 * Default constructor
	 */
	public XAdES122Path() {
		// empty
	}

	@Override
	public DSSNamespace getNamespace() {
		return XAdESNamespace.XADES_122;
	}

	@Override
	public String getSignedPropertiesUri() {
		return "http://uri.etsi.org/01903/v1.2.2#SignedProperties";
	}

	@Override
	public String getCounterSignatureUri() {
		return "http://uri.etsi.org/01903#CountersignedSignature";
	}

	@Override
	public XPathQuery getQualifyingPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public XPathQuery getSignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES);
	}

	@Override
	public XPathQuery getSignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public XPathQuery getSigningTimePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNING_TIME);
	}

	@Override
	public XPathQuery getSigningCertificatePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNING_CERTIFICATE);
	}

	@Override
	public XPathQuery getSigningCertificateChildren() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNING_CERTIFICATE, XAdES122Element.CERT);
	}

	@Override
	public XPathQuery getSigningCertificateV2Path() {
		return null;
	}

	@Override
	public XPathQuery getSigningCertificateV2Children() {
		return null;
	}

	@Override
	public XPathQuery getSignatureProductionPlacePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNATURE_PRODUCTION_PLACE);
	}

	@Override
	public XPathQuery getSignatureProductionPlaceV2Path() {
		return null;
	}

	@Override
	public XPathQuery getSignaturePolicyIdentifierPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNATURE_POLICY_IDENTIFIER);
	}

	@Override
	public XPathQuery getSignerRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNER_ROLE);
	}

	@Override
	public XPathQuery getSignerRoleV2Path() {
		return null;
	}

	@Override
	public XPathQuery getClaimedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNER_ROLE, XAdES122Element.CLAIMED_ROLES, XAdES122Element.CLAIMED_ROLE);
	}

	@Override
	public XPathQuery getClaimedRoleV2Path() {
		return null;
	}

	@Override
	public XPathQuery getSignedAssertionPath() {
		return null;
	}

	@Override
	public XPathQuery getCertifiedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNER_ROLE, XAdES122Element.CERTIFIED_ROLES, XAdES122Element.CERTIFIED_ROLE);
	}

	@Override
	public XPathQuery getCertifiedRoleV2Path() {
		return null;
	}

	@Override
	public XPathQuery getSignedDataObjectPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES);
	}

	@Override
	public XPathQuery getAllDataObjectsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.ALL_DATA_OBJECTS_TIMESTAMP);
	}

	@Override
	public XPathQuery getIndividualDataObjectsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
	}

	@Override
	public XPathQuery getDataObjectFormat() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.DATA_OBJECT_FORMAT);
	}

	@Override
	public XPathQuery getDataObjectFormatMimeType() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.DATA_OBJECT_FORMAT, XAdES122Element.MIME_TYPE);
	}

	@Override
	public XPathQuery getDataObjectFormatObjectIdentifier() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.DATA_OBJECT_FORMAT, XAdES122Element.OBJECT_IDENTIFIER);
	}

	@Override
	public XPathQuery getCommitmentTypeIndicationPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.COMMITMENT_TYPE_INDICATION);
	}

	@Override
	public XPathQuery getUnsignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES);
	}

	@Override
	public XPathQuery getUnsignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public XPathQuery getCounterSignaturePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.COUNTER_SIGNATURE);
	}

	@Override
	public XPathQuery getAttributeRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.ATTRIBUTE_REVOCATION_REFS);
	}

	@Override
	public XPathQuery getCompleteRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.COMPLETE_REVOCATION_REFS);
	}

	@Override
	public XPathQuery getCompleteCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.COMPLETE_CERTIFICATE_REFS);
	}

	@Override
	public XPathQuery getCompleteCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.COMPLETE_CERTIFICATE_REFS, XAdES122Element.CERT_REFS, XAdES122Element.CERT);
	}

	@Override
	public XPathQuery getCompleteCertificateRefsV2Path() {
		return null;
	}

	@Override
	public XPathQuery getCompleteCertificateRefsV2CertPath() {
		return null;
	}

	@Override
	public XPathQuery getAttributeCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.ATTRIBUTE_CERTIFICATE_REFS);
	}

	@Override
	public XPathQuery getAttributeCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.ATTRIBUTE_CERTIFICATE_REFS, XAdES122Element.CERT_REFS, XAdES122Element.CERT);
	}

	@Override
	public XPathQuery getAttributeCertificateRefsV2Path() {
		return null;
	}

	@Override
	public XPathQuery getAttributeCertificateRefsV2CertPath() {
		return null;
	}

	@Override
	public XPathQuery getCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.CERTIFICATE_VALUES);
	}

	@Override
	public XPathQuery getRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.REVOCATION_VALUES);
	}

	@Override
	public XPathQuery getEncapsulatedCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.CERTIFICATE_VALUES, XAdES122Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getAttrAuthoritiesCertValuesPath() {
		return null;
	}

	@Override
	public XPathQuery getEncapsulatedAttrAuthoritiesCertValuesPath() {
		return null;
	}

	@Override
	public XPathQuery getEncapsulatedTimeStampValidationDataCertValuesPath() {
		return null;
	}

	@Override
	public XPathQuery getAttributeRevocationValuesPath() {
		return null;
	}

	@Override
	public XPathQuery getTimeStampValidationDataRevocationValuesPath() {
		return null;
	}

	@Override
	public XPathQuery getAnyValidationDataPath() {
		return null;
	}

	@Override
	public XPathQuery getEncapsulatedAnyValidationDataCertValuesPath() {
		return null;
	}

	@Override
	public XPathQuery getAnyValidationDataRevocationValuesPath() {
		return null;
	}

	@Override
	public XPathQuery getSignatureTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNATURE_TIMESTAMP);
	}

	@Override
	public XPathQuery getSigAndRefsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIG_AND_REFS_TIMESTAMP);
	}

	@Override
	public XPathQuery getSigAndRefsTimestampV2Path() {
		return null;
	}

	@Override
	public XPathQuery getRefsOnlyTimestampPath() {
		return null;
	}

	@Override
	public XPathQuery getRefsOnlyTimestampV2Path() {
		return null;
	}

	@Override
	public XPathQuery getArchiveTimestampPath() {
		return null;
	}

	@Override
	public XPathQuery getSealingEvidenceRecordsPath() {
		return null;
	}

	@Override
	public XPathQuery getTimestampValidationDataPath() {
		return null;
	}

	@Override
	public XPathQuery getSignaturePolicyStorePath() {
		return null;
	}

	// ------------------------------------------------

	@Override
	public XPathQuery getCurrentCRLValuesChildren() {
		return fromCurrentPosition(XAdES122Element.CRL_VALUES, XAdES122Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public XPathQuery getCurrentCRLRefsChildren() {
		return fromCurrentPosition(XAdES122Element.CRL_REFS, XAdES122Element.CRL_REF);
	}

	@Override
	public XPathQuery getCurrentCRLRefCRLIdentifier() {
		return fromCurrentPosition(XAdES122Element.CRL_IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentCRLRefCRLIdentifierIssuer() {
		return fromCurrentPosition(XAdES122Element.CRL_IDENTIFIER, XAdES122Element.ISSUER);
	}

	@Override
	public XPathQuery getCurrentCRLRefCRLIdentifierIssueTime() {
		return fromCurrentPosition(XAdES122Element.CRL_IDENTIFIER, XAdES122Element.ISSUE_TIME);
	}

	@Override
	public XPathQuery getCurrentCRLRefCRLIdentifierNumber() {
		return fromCurrentPosition(XAdES122Element.CRL_IDENTIFIER, XAdES122Element.NUMBER);
	}

	@Override
	public XPathQuery getCurrentOCSPRefsChildren() {
		return fromCurrentPosition(XAdES122Element.OCSP_REFS, XAdES122Element.OCSP_REF);
	}

	@Override
	public XPathQuery getCurrentOCSPValuesChildren() {
		return fromCurrentPosition(XAdES122Element.OCSP_VALUES, XAdES122Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public XPathQuery getCurrentOCSPRefResponderID() {
		return fromCurrentPosition(XAdES122Element.OCSP_IDENTIFIER, XAdES122Element.RESPONDER_ID);
	}

	@Override
	public XPathQuery getCurrentOCSPRefResponderIDByName() {
		return null;
	}

	@Override
	public XPathQuery getCurrentOCSPRefResponderIDByKey() {
		return null;
	}

	@Override
	public XPathQuery getCurrentOCSPRefProducedAt() {
		return fromCurrentPosition(XAdES122Element.OCSP_IDENTIFIER, XAdES122Element.PRODUCED_AT);
	}

	@Override
	public XPathQuery getCurrentDigestAlgAndValue() {
		return fromCurrentPosition(XAdES122Element.DIGEST_ALG_AND_VALUE);
	}

	@Override
	public XPathQuery getCurrentCertRefsCertChildren() {
		return fromCurrentPosition(XAdES122Element.CERT_REFS, XAdES122Element.CERT);
	}

	@Override
	public XPathQuery getCurrentCertRefs141CertChildren() {
		return null;
	}

	@Override
	public XPathQuery getCurrentCertChildren() {
		return fromCurrentPosition(XAdES122Element.CERT);
	}

	@Override
	public XPathQuery getCurrentCertDigest() {
		return fromCurrentPosition(XAdES122Element.CERT_DIGEST);
	}

	@Override
	public XPathQuery getCurrentEncapsulatedTimestamp() {
		return fromCurrentPosition(XAdES122Element.ENCAPSULATED_TIMESTAMP);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyId() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_ID, XAdES122Element.IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyDigestAlgAndValue() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_HASH);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicySPURI() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_QUALIFIERS, XAdES122Element.SIG_POLICY_QUALIFIER,
				XAdES122Element.SP_URI);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicySPUserNotice() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_QUALIFIERS, XAdES122Element.SIG_POLICY_QUALIFIER,
				XAdES122Element.SP_USER_NOTICE);
	}

	@Override
	public XPathQuery getCurrentSPUserNoticeNoticeRefOrganization() {
		return fromCurrentPosition(XAdES122Element.NOTICE_REF, XAdES122Element.ORGANIZATION);
	}

	@Override
	public XPathQuery getCurrentSPUserNoticeNoticeRefNoticeNumbers() {
		return fromCurrentPosition(XAdES122Element.NOTICE_REF, XAdES122Element.NOTICE_NUMBERS);
	}

	@Override
	public XPathQuery getCurrentSPUserNoticeExplicitText() {
		return fromCurrentPosition(XAdES122Element.EXPLICIT_TEXT);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicySPDocSpecification() {
		return null;
	}

	@Override
	public XPathQuery getCurrentSignaturePolicySPDocSpecificationIdentifier() {
		return null;
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyDescription() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_ID, XAdES122Element.DESCRIPTION);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyDocumentationReferences() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_ID, XAdES122Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyImplied() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_IMPLIED);
	}
	
	@Override
	public XPathQuery getCurrentSignaturePolicyTransforms() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XMLDSigElement.TRANSFORMS);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyQualifiers() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_QUALIFIERS);
	}

	@Override
	public XPathQuery getCurrentIssuerSerialIssuerNamePath() {
		return fromCurrentPosition(XAdES122Element.ISSUER_SERIAL, XMLDSigElement.X509_ISSUER_NAME);
	}

	@Override
	public XPathQuery getCurrentIssuerSerialSerialNumberPath() {
		return fromCurrentPosition(XAdES122Element.ISSUER_SERIAL, XMLDSigElement.X509_SERIAL_NUMBER);
	}

	@Override
	public XPathQuery getCurrentIssuerSerialV2Path() {
		return null;
	}

	@Override
	public XPathQuery getCurrentCommitmentIdentifierPath() {
		return fromCurrentPosition(XAdES122Element.COMMITMENT_TYPE_ID, XAdES122Element.IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentCommitmentDescriptionPath() {
		return fromCurrentPosition(XAdES122Element.COMMITMENT_TYPE_ID, XAdES122Element.DESCRIPTION);
	}

	@Override
	public XPathQuery getCurrentCommitmentDocumentationReferencesPath() {
		return fromCurrentPosition(XAdES122Element.COMMITMENT_TYPE_ID, XAdES122Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public XPathQuery getCurrentDocumentationReference() {
		return fromCurrentPosition(XAdES122Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public XPathQuery getCurrentCommitmentObjectReferencesPath() {
		return fromCurrentPosition(XAdES122Element.OBJECT_REFERENCE);
	}

	@Override
	public XPathQuery getCurrentCommitmentAllSignedDataObjectsPath() {
		return fromCurrentPosition(XAdES122Element.ALL_SIGNED_DATA_OBJECTS);
	}

	@Override
	public XPathQuery getCurrentInclude() {
		return fromCurrentPosition(XAdES122Element.INCLUDE);
	}

	@Override
	public XPathQuery getCurrentEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES122Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getCurrentCertificateValuesEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES122Element.CERTIFICATE_VALUES, XAdES122Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getCurrentEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES122Element.OCSP_VALUES, XAdES122Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public XPathQuery getCurrentRevocationValuesEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES122Element.REVOCATION_VALUES, XAdES122Element.OCSP_VALUES, XAdES122Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public XPathQuery getCurrentEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES122Element.CRL_VALUES, XAdES122Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public XPathQuery getCurrentRevocationValuesEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES122Element.REVOCATION_VALUES, XAdES122Element.CRL_VALUES, XAdES122Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public XPathQuery getCurrentQualifyingPropertiesPath() {
		return fromCurrentPosition(XAdES122Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public XPathQuery getCurrentDescription() {
		return fromCurrentPosition(XAdES122Element.DESCRIPTION);
	}

	@Override
	public XPathQuery getCurrentObjectIdentifier() {
		return fromCurrentPosition(XAdES122Element.OBJECT_IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentMimeType() {
		return fromCurrentPosition(XAdES122Element.MIME_TYPE);
	}

	@Override
	public XPathQuery getCurrentEncoding() {
		return fromCurrentPosition(XAdES122Element.ENCODING);
	}

	@Override
	public XPathQuery getCurrentSPDocSpecification() {
		return null;
	}

	@Override
	public XPathQuery getCurrentIdentifier() {
		return fromCurrentPosition(XAdES122Element.IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentSPDocSpecificationIdentifier() {
		return null;
	}

	@Override
	public XPathQuery getCurrentSPDocSpecificationDescription() {
		return null;
	}

	@Override
	public XPathQuery getCurrentDocumentationReferenceElements() {
		return null;
	}

	@Override
	public XPathQuery getCurrentSPDocSpecificationDocumentationReferenceElements() {
		return null;
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyDocument() {
		return null;
	}

	@Override
	public XPathQuery getCurrentSigPolDocLocalURI() {
		return null;
	}

}
