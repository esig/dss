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
	public String getQualifyingPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public String getSignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES);
	}

	@Override
	public String getSignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public String getSigningTimePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNING_TIME);
	}

	@Override
	public String getSigningCertificatePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNING_CERTIFICATE);
	}

	@Override
	public String getSigningCertificateChildren() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNING_CERTIFICATE, XAdES122Element.CERT);
	}

	@Override
	public String getSigningCertificateV2Path() {
		return null;
	}

	@Override
	public String getSigningCertificateV2Children() {
		return null;
	}

	@Override
	public String getSignatureProductionPlacePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNATURE_PRODUCTION_PLACE);
	}

	@Override
	public String getSignatureProductionPlaceV2Path() {
		return null;
	}

	@Override
	public String getSignaturePolicyIdentifierPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNATURE_POLICY_IDENTIFIER);
	}

	@Override
	public String getSignerRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNER_ROLE);
	}

	@Override
	public String getSignerRoleV2Path() {
		return null;
	}

	@Override
	public String getClaimedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNER_ROLE, XAdES122Element.CLAIMED_ROLES, XAdES122Element.CLAIMED_ROLE);
	}

	@Override
	public String getClaimedRoleV2Path() {
		return null;
	}

	@Override
	public String getSignedAssertionPath() {
		return null;
	}

	@Override
	public String getCertifiedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNER_ROLE, XAdES122Element.CERTIFIED_ROLES, XAdES122Element.CERTIFIED_ROLE);
	}

	@Override
	public String getCertifiedRoleV2Path() {
		return null;
	}

	@Override
	public String getSignedDataObjectPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES);
	}

	@Override
	public String getDataObjectFormat() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.DATA_OBJECT_FORMAT);
	}

	@Override
	public String getDataObjectFormatMimeType() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.DATA_OBJECT_FORMAT, XAdES122Element.MIME_TYPE);
	}

	@Override
	public String getDataObjectFormatObjectIdentifier() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.DATA_OBJECT_FORMAT, XAdES122Element.OBJECT_IDENTIFIER);
	}

	@Override
	public String getCommitmentTypeIndicationPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.SIGNED_PROPERTIES,
				XAdES122Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES122Element.COMMITMENT_TYPE_INDICATION);
	}

	@Override
	public String getUnsignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES);
	}

	@Override
	public String getUnsignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public String getCounterSignaturePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.COUNTER_SIGNATURE);
	}

	@Override
	public String getAttributeRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.ATTRIBUTE_REVOCATION_REFS);
	}

	@Override
	public String getCompleteRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.COMPLETE_REVOCATION_REFS);
	}

	@Override
	public String getCompleteCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.COMPLETE_CERTIFICATE_REFS);
	}

	@Override
	public String getCompleteCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.COMPLETE_CERTIFICATE_REFS, XAdES122Element.CERT_REFS, XAdES122Element.CERT);
	}

	@Override
	public String getCompleteCertificateRefsV2Path() {
		return null;
	}

	@Override
	public String getCompleteCertificateRefsV2CertPath() {
		return null;
	}

	@Override
	public String getAttributeCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.ATTRIBUTE_CERTIFICATE_REFS);
	}

	@Override
	public String getAttributeCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.ATTRIBUTE_CERTIFICATE_REFS, XAdES122Element.CERT_REFS, XAdES122Element.CERT);
	}

	@Override
	public String getAttributeCertificateRefsV2Path() {
		return null;
	}

	@Override
	public String getAttributeCertificateRefsV2CertPath() {
		return null;
	}

	@Override
	public String getCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.CERTIFICATE_VALUES);
	}

	@Override
	public String getRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.REVOCATION_VALUES);
	}

	@Override
	public String getEncapsulatedCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.CERTIFICATE_VALUES, XAdES122Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getAttrAuthoritiesCertValuesPath() {
		return null;
	}

	@Override
	public String getEncapsulatedAttrAuthoritiesCertValuesPath() {
		return null;
	}

	@Override
	public String getEncapsulatedTimeStampValidationDataCertValuesPath() {
		return null;
	}

	@Override
	public String getAttributeRevocationValuesPath() {
		return null;
	}

	@Override
	public String getTimeStampValidationDataRevocationValuesPath() {
		return null;
	}

	@Override
	public String getEncapsulatedAnyValidationDataCertValuesPath() {
		return null;
	}

	@Override
	public String getAnyValidationDataRevocationValuesPath() {
		return null;
	}

	@Override
	public String getSignatureTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIGNATURE_TIMESTAMP);
	}

	@Override
	public String getSigAndRefsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES122Element.QUALIFYING_PROPERTIES, XAdES122Element.UNSIGNED_PROPERTIES,
				XAdES122Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES122Element.SIG_AND_REFS_TIMESTAMP);
	}

	@Override
	public String getSigAndRefsTimestampV2Path() {
		return null;
	}

	@Override
	public String getRefsOnlyTimestampPath() {
		return null;
	}

	@Override
	public String getRefsOnlyTimestampV2Path() {
		return null;
	}

	@Override
	public String getArchiveTimestampPath() {
		return null;
	}

	@Override
	public String getSealingEvidenceRecordsPath() {
		return null;
	}

	@Override
	public String getTimestampValidationDataPath() {
		return null;
	}

	@Override
	public String getSignaturePolicyStorePath() {
		return null;
	}

	// ------------------------------------------------

	@Override
	public String getCurrentCRLValuesChildren() {
		return fromCurrentPosition(XAdES122Element.CRL_VALUES, XAdES122Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentCRLRefsChildren() {
		return fromCurrentPosition(XAdES122Element.CRL_REFS, XAdES122Element.CRL_REF);
	}

	@Override
	public String getCurrentOCSPRefsChildren() {
		return fromCurrentPosition(XAdES122Element.OCSP_REFS, XAdES122Element.OCSP_REF);
	}

	@Override
	public String getCurrentOCSPValuesChildren() {
		return fromCurrentPosition(XAdES122Element.OCSP_VALUES, XAdES122Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentOCSPRefResponderID() {
		return fromCurrentPosition(XAdES122Element.OCSP_IDENTIFIER, XAdES122Element.RESPONDER_ID);
	}

	@Override
	public String getCurrentOCSPRefResponderIDByName() {
		return null;
	}

	@Override
	public String getCurrentOCSPRefResponderIDByKey() {
		return null;
	}

	@Override
	public String getCurrentOCSPRefProducedAt() {
		return fromCurrentPosition(XAdES122Element.OCSP_IDENTIFIER, XAdES122Element.PRODUCED_AT);
	}

	@Override
	public String getCurrentDigestAlgAndValue() {
		return fromCurrentPosition(XAdES122Element.DIGEST_ALG_AND_VALUE);
	}

	@Override
	public String getCurrentCertRefsCertChildren() {
		return fromCurrentPosition(XAdES122Element.CERT_REFS, XAdES122Element.CERT);
	}

	@Override
	public String getCurrentCertRefs141CertChildren() {
		return null;
	}

	@Override
	public String getCurrentCertChildren() {
		return fromCurrentPosition(XAdES122Element.CERT);
	}

	@Override
	public String getCurrentCertDigest() {
		return fromCurrentPosition(XAdES122Element.CERT_DIGEST);
	}

	@Override
	public String getCurrentEncapsulatedTimestamp() {
		return fromCurrentPosition(XAdES122Element.ENCAPSULATED_TIMESTAMP);
	}

	@Override
	public String getCurrentSignaturePolicyId() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_ID, XAdES122Element.IDENTIFIER);
	}

	@Override
	public String getCurrentSignaturePolicyDigestAlgAndValue() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_HASH);
	}

	@Override
	public String getCurrentSignaturePolicySPURI() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_QUALIFIERS, XAdES122Element.SIG_POLICY_QUALIFIER,
				XAdES122Element.SP_URI);
	}

	@Override
	public String getCurrentSignaturePolicySPUserNotice() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_QUALIFIERS, XAdES122Element.SIG_POLICY_QUALIFIER,
				XAdES122Element.SP_USER_NOTICE);
	}

	@Override
	public String getCurrentSPUserNoticeNoticeRefOrganization() {
		return fromCurrentPosition(XAdES122Element.NOTICE_REF, XAdES122Element.ORGANIZATION);
	}

	@Override
	public String getCurrentSPUserNoticeNoticeRefNoticeNumbers() {
		return fromCurrentPosition(XAdES122Element.NOTICE_REF, XAdES122Element.NOTICE_NUMBERS);
	}

	@Override
	public String getCurrentSPUserNoticeExplicitText() {
		return fromCurrentPosition(XAdES122Element.EXPLICIT_TEXT);
	}

	@Override
	public String getCurrentSignaturePolicySPDocSpecification() {
		return null;
	}

	@Override
	public String getCurrentSignaturePolicySPDocSpecificationIdentifier() {
		return null;
	}

	@Override
	public String getCurrentSignaturePolicyDescription() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_ID, XAdES122Element.DESCRIPTION);
	}

	@Override
	public String getCurrentSignaturePolicyDocumentationReferences() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_ID, XAdES122Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public String getCurrentSignaturePolicyImplied() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_IMPLIED);
	}
	
	@Override
	public String getCurrentSignaturePolicyTransforms() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XMLDSigElement.TRANSFORMS);
	}

	@Override
	public String getCurrentSignaturePolicyQualifiers() {
		return fromCurrentPosition(XAdES122Element.SIGNATURE_POLICY_ID, XAdES122Element.SIG_POLICY_QUALIFIERS);
	}

	@Override
	public String getCurrentIssuerSerialIssuerNamePath() {
		return fromCurrentPosition(XAdES122Element.ISSUER_SERIAL, XMLDSigElement.X509_ISSUER_NAME);
	}

	@Override
	public String getCurrentIssuerSerialSerialNumberPath() {
		return fromCurrentPosition(XAdES122Element.ISSUER_SERIAL, XMLDSigElement.X509_SERIAL_NUMBER);
	}

	@Override
	public String getCurrentIssuerSerialV2Path() {
		return null;
	}

	@Override
	public String getCurrentCommitmentIdentifierPath() {
		return fromCurrentPosition(XAdES122Element.COMMITMENT_TYPE_ID, XAdES122Element.IDENTIFIER);
	}

	@Override
	public String getCurrentCommitmentDescriptionPath() {
		return fromCurrentPosition(XAdES122Element.COMMITMENT_TYPE_ID, XAdES122Element.DESCRIPTION);
	}

	@Override
	public String getCurrentCommitmentDocumentationReferencesPath() {
		return fromCurrentPosition(XAdES122Element.COMMITMENT_TYPE_ID, XAdES122Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public String getCurrentDocumentationReference() {
		return fromCurrentPosition(XAdES122Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public String getCurrentCommitmentObjectReferencesPath() {
		return fromCurrentPosition(XAdES122Element.OBJECT_REFERENCE);
	}

	@Override
	public String getCurrentCommitmentAllSignedDataObjectsPath() {
		return fromCurrentPosition(XAdES122Element.ALL_SIGNED_DATA_OBJECTS);
	}

	@Override
	public String getCurrentInclude() {
		return fromCurrentPosition(XAdES122Element.INCLUDE);
	}

	@Override
	public String getCurrentEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES122Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getCurrentCertificateValuesEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES122Element.CERTIFICATE_VALUES, XAdES122Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getCurrentEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES122Element.OCSP_VALUES, XAdES122Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentRevocationValuesEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES122Element.REVOCATION_VALUES, XAdES122Element.OCSP_VALUES, XAdES122Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES122Element.CRL_VALUES, XAdES122Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentRevocationValuesEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES122Element.REVOCATION_VALUES, XAdES122Element.CRL_VALUES, XAdES122Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentQualifyingPropertiesPath() {
		return fromCurrentPosition(XAdES122Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public String getCurrentDescription() {
		return fromCurrentPosition(XAdES122Element.DESCRIPTION);
	}

	@Override
	public String getCurrentObjectIdentifier() {
		return fromCurrentPosition(XAdES122Element.OBJECT_IDENTIFIER);
	}

	@Override
	public String getCurrentMimeType() {
		return fromCurrentPosition(XAdES122Element.MIME_TYPE);
	}

	@Override
	public String getCurrentEncoding() {
		return fromCurrentPosition(XAdES122Element.ENCODING);
	}

	@Override
	public String getCurrentSPDocSpecification() {
		return null;
	}

	@Override
	public String getCurrentIdentifier() {
		return fromCurrentPosition(XAdES122Element.IDENTIFIER);
	}

	@Override
	public String getCurrentSPDocSpecificationIdentifier() {
		return null;
	}

	@Override
	public String getCurrentSPDocSpecificationDescription() {
		return null;
	}

	@Override
	public String getCurrentDocumentationReferenceElements() {
		return null;
	}

	@Override
	public String getCurrentSPDocSpecificationDocumentationReferenceElements() {
		return null;
	}

	@Override
	public String getCurrentSignaturePolicyDocument() {
		return null;
	}

	@Override
	public String getCurrentSigPolDocLocalURI() {
		return null;
	}

}
