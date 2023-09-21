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
package eu.europa.esig.xades.definition.xades132;

import eu.europa.esig.dss.jaxb.common.definition.AbstractPath;
import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;
import eu.europa.esig.xades.definition.XAdESNamespace;
import eu.europa.esig.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.xmldsig.definition.XMLDSigElement;
import eu.europa.esig.xades.definition.XAdESPath;
import eu.europa.esig.xades.XAdES319132Utils;
import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;

/**
 * XAdES 1.3.2 paths
 */
public class XAdES132Path extends AbstractPath implements XAdESPath {

	private static final long serialVersionUID = 1878591854613359863L;

	// TODO find a proper way (namespace independent)
	/** Gets all signatures without counter signatures */
	public static final String ALL_SIGNATURE_WITH_NO_COUNTERSIGNATURE_AS_PARENT_PATH = allNotParent(XMLDSigElement.SIGNATURE,
			XAdES132Element.COUNTER_SIGNATURE);

	/**
	 * Default constructor
	 */
	public XAdES132Path() {
		// empty
	}

	@Override
	public DSSNamespace getNamespace() {
		return XAdESNamespace.XADES_132;
	}

	@Override
	public String getSignedPropertiesUri() {
		return "http://uri.etsi.org/01903#SignedProperties";
	}

	@Override
	public String getCounterSignatureUri() {
		return "http://uri.etsi.org/01903#CountersignedSignature";
	}

	@Override
	public String getQualifyingPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public String getSignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES);
	}

	@Override
	public String getSignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public String getSigningTimePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_TIME);
	}

	@Override
	public String getSigningCertificatePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE);
	}

	@Override
	public String getSigningCertificateChildren() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE, XAdES132Element.CERT);
	}

	@Override
	public String getSigningCertificateV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE_V2);
	}

	@Override
	public String getSigningCertificateV2Children() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE_V2, XAdES132Element.CERT);
	}

	@Override
	public String getSignatureProductionPlacePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_PRODUCTION_PLACE);
	}

	@Override
	public String getSignatureProductionPlaceV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_PRODUCTION_PLACE_V2);
	}

	@Override
	public String getSignaturePolicyIdentifierPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_POLICY_IDENTIFIER);
	}

	@Override
	public String getSignerRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE);
	}

	@Override
	public String getSignerRoleV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE_V2);
	}

	@Override
	public String getClaimedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE, XAdES132Element.CLAIMED_ROLES, XAdES132Element.CLAIMED_ROLE);
	}

	@Override
	public String getClaimedRoleV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE_V2, XAdES132Element.CLAIMED_ROLES, XAdES132Element.CLAIMED_ROLE);
	}
	
	@Override
	public String getSignedAssertionPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE_V2, XAdES132Element.SIGNED_ASSERTIONS, XAdES132Element.SIGNED_ASSERTION);
	}

	@Override
	public String getCertifiedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE, XAdES132Element.CERTIFIED_ROLES, XAdES132Element.CERTIFIED_ROLE);
	}

	@Override
	public String getCertifiedRoleV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE_V2, XAdES132Element.CERTIFIED_ROLES_V2,
				XAdES132Element.CERTIFIED_ROLE);
	}

	@Override
	public String getSignedDataObjectPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES);
	}

	@Override
	public String getDataObjectFormat() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.DATA_OBJECT_FORMAT);
	}

	@Override
	public String getDataObjectFormatMimeType() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.DATA_OBJECT_FORMAT, XAdES132Element.MIME_TYPE);
	}

	@Override
	public String getDataObjectFormatObjectIdentifier() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.DATA_OBJECT_FORMAT, XAdES132Element.OBJECT_IDENTIFIER);
	}

	@Override
	public String getCommitmentTypeIndicationPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.COMMITMENT_TYPE_INDICATION);
	}

	@Override
	public String getUnsignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES);
	}

	@Override
	public String getUnsignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public String getCounterSignaturePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.COUNTER_SIGNATURE);
	}

	@Override
	public String getAttributeRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_REVOCATION_REFS);
	}

	@Override
	public String getCompleteRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.COMPLETE_REVOCATION_REFS);
	}

	@Override
	public String getCompleteCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.COMPLETE_CERTIFICATE_REFS);
	}

	@Override
	public String getCompleteCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.COMPLETE_CERTIFICATE_REFS, XAdES132Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public String getCompleteCertificateRefsV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2);
	}

	@Override
	public String getCompleteCertificateRefsV2CertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2, XAdES141Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public String getAttributeCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_CERTIFICATE_REFS);
	}

	@Override
	public String getAttributeCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_CERTIFICATE_REFS, XAdES132Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public String getAttributeCertificateRefsV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2);
	}

	@Override
	public String getAttributeCertificateRefsV2CertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2, XAdES141Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public String getCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.CERTIFICATE_VALUES);
	}

	@Override
	public String getRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.REVOCATION_VALUES);
	}

	@Override
	public String getEncapsulatedCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.CERTIFICATE_VALUES, XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getAttrAuthoritiesCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTR_AUTHORITIES_CERT_VALUES);
	}

	@Override
	public String getEncapsulatedAttrAuthoritiesCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTR_AUTHORITIES_CERT_VALUES, XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getEncapsulatedTimeStampValidationDataCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.TIMESTAMP_VALIDATION_DATA, XAdES132Element.CERTIFICATE_VALUES,
				XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getAttributeRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_REVOCATION_VALUES);
	}

	@Override
	public String getTimeStampValidationDataRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.TIMESTAMP_VALIDATION_DATA, XAdES132Element.REVOCATION_VALUES);
	}

	@Override
	public String getSignatureTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_TIMESTAMP);
	}

	@Override
	public String getSigAndRefsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIG_AND_REFS_TIMESTAMP);
	}

	@Override
	public String getSigAndRefsTimestampV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.SIG_AND_REFS_TIMESTAMP_V2);
	}

	@Override
	public String getRefsOnlyTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.REFS_ONLY_TIMESTAMP);
	}

	@Override
	public String getRefsOnlyTimestampV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.REFS_ONLY_TIMESTAMP_V2);
	}

	@Override
	public String getArchiveTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ARCHIVE_TIMESTAMP);
	}

	@Override
	public String getTimestampValidationDataPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.TIMESTAMP_VALIDATION_DATA);
	}

	@Override
	public String getSignaturePolicyStorePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES,
				XAdES132Element.UNSIGNED_PROPERTIES, XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES,
				XAdES141Element.SIGNATURE_POLICY_STORE);
	}

	// ------------------------------------------------

	@Override
	public String getCurrentCRLValuesChildren() {
		return fromCurrentPosition(XAdES132Element.CRL_VALUES, XAdES132Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentCRLRefsChildren() {
		return fromCurrentPosition(XAdES132Element.CRL_REFS, XAdES132Element.CRL_REF);
	}

	@Override
	public String getCurrentOCSPRefsChildren() {
		return fromCurrentPosition(XAdES132Element.OCSP_REFS, XAdES132Element.OCSP_REF);
	}

	@Override
	public String getCurrentOCSPValuesChildren() {
		return fromCurrentPosition(XAdES132Element.OCSP_VALUES, XAdES132Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentOCSPRefResponderID() {
		return fromCurrentPosition(XAdES132Element.OCSP_IDENTIFIER, XAdES132Element.RESPONDER_ID);
	}

	@Override
	public String getCurrentOCSPRefResponderIDByName() {
		return fromCurrentPosition(XAdES132Element.OCSP_IDENTIFIER, XAdES132Element.RESPONDER_ID, XAdES132Element.BY_NAME);
	}

	@Override
	public String getCurrentOCSPRefResponderIDByKey() {
		return fromCurrentPosition(XAdES132Element.OCSP_IDENTIFIER, XAdES132Element.RESPONDER_ID, XAdES132Element.BY_KEY);
	}

	@Override
	public String getCurrentOCSPRefProducedAt() {
		return fromCurrentPosition(XAdES132Element.OCSP_IDENTIFIER, XAdES132Element.PRODUCED_AT);
	}

	@Override
	public String getCurrentDigestAlgAndValue() {
		return fromCurrentPosition(XAdES132Element.DIGEST_ALG_AND_VALUE);
	}

	@Override
	public String getCurrentCertRefsCertChildren() {
		return fromCurrentPosition(XAdES132Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public String getCurrentCertRefs141CertChildren() {
		return fromCurrentPosition(XAdES141Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public String getCurrentCertChildren() {
		return fromCurrentPosition(XAdES132Element.CERT);
	}

	@Override
	public String getCurrentCertDigest() {
		return fromCurrentPosition(XAdES132Element.CERT_DIGEST);
	}

	@Override
	public String getCurrentEncapsulatedTimestamp() {
		return fromCurrentPosition(XAdES132Element.ENCAPSULATED_TIMESTAMP);
	}

	@Override
	public String getCurrentSignaturePolicyId() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_ID, XAdES132Element.IDENTIFIER);
	}

	@Override
	public String getCurrentSignaturePolicyDigestAlgAndValue() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_HASH);
	}

	@Override
	public String getCurrentSignaturePolicySPURI() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS, XAdES132Element.SIG_POLICY_QUALIFIER,
				XAdES132Element.SP_URI);
	}

	@Override
	public String getCurrentSignaturePolicySPUserNotice() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS, XAdES132Element.SIG_POLICY_QUALIFIER,
				XAdES132Element.SP_USER_NOTICE);
	}

	@Override
	public String getCurrentSPUserNoticeNoticeRefOrganization() {
		return fromCurrentPosition(XAdES132Element.NOTICE_REF, XAdES132Element.ORGANIZATION);
	}

	@Override
	public String getCurrentSPUserNoticeNoticeRefNoticeNumbers() {
		return fromCurrentPosition(XAdES132Element.NOTICE_REF, XAdES132Element.NOTICE_NUMBERS);
	}

	@Override
	public String getCurrentSPUserNoticeExplicitText() {
		return fromCurrentPosition(XAdES132Element.EXPLICIT_TEXT);
	}

	@Override
	public String getCurrentSignaturePolicySPDocSpecification() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS,
				XAdES132Element.SIG_POLICY_QUALIFIER, XAdES141Element.SP_DOC_SPECIFICATION);
	}

	@Override
	public String getCurrentSignaturePolicySPDocSpecificationIdentifier() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS,
				XAdES132Element.SIG_POLICY_QUALIFIER, XAdES141Element.SP_DOC_SPECIFICATION, XAdES132Element.IDENTIFIER);
	}

	@Override
	public String getCurrentSignaturePolicyDescription() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_ID, XAdES132Element.DESCRIPTION);
	}

	@Override
	public String getCurrentSignaturePolicyDocumentationReferences() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_ID, XAdES132Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public String getCurrentSignaturePolicyImplied() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_IMPLIED);
	}
	
	@Override
	public String getCurrentSignaturePolicyTransforms() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XMLDSigElement.TRANSFORMS);
	}

	@Override
	public String getCurrentSignaturePolicyQualifiers() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS);
	}

	@Override
	public String getCurrentIssuerSerialIssuerNamePath() {
		return fromCurrentPosition(XAdES132Element.ISSUER_SERIAL, XMLDSigElement.X509_ISSUER_NAME);
	}

	@Override
	public String getCurrentIssuerSerialSerialNumberPath() {
		return fromCurrentPosition(XAdES132Element.ISSUER_SERIAL, XMLDSigElement.X509_SERIAL_NUMBER);
	}

	@Override
	public String getCurrentIssuerSerialV2Path() {
		return fromCurrentPosition(XAdES132Element.ISSUER_SERIAL_V2);
	}

	@Override
	public String getCurrentCommitmentIdentifierPath() {
		return fromCurrentPosition(XAdES132Element.COMMITMENT_TYPE_ID, XAdES132Element.IDENTIFIER);
	}

	@Override
	public String getCurrentCommitmentDescriptionPath() {
		return fromCurrentPosition(XAdES132Element.COMMITMENT_TYPE_ID, XAdES132Element.DESCRIPTION);
	}

	@Override
	public String getCurrentCommitmentDocumentationReferencesPath() {
		return fromCurrentPosition(XAdES132Element.COMMITMENT_TYPE_ID, XAdES132Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public String getCurrentDocumentationReference() {
		return fromCurrentPosition(XAdES132Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public String getCurrentCommitmentObjectReferencesPath() {
		return fromCurrentPosition(XAdES132Element.OBJECT_REFERENCE);
	}

	@Override
	public String getCurrentCommitmentAllSignedDataObjectsPath() {
		return fromCurrentPosition(XAdES132Element.ALL_SIGNED_DATA_OBJECTS);
	}

	@Override
	public String getCurrentInclude() {
		return fromCurrentPosition(XAdES132Element.INCLUDE);
	}

	@Override
	public String getCurrentEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getCurrentCertificateValuesEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES132Element.CERTIFICATE_VALUES, XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getCurrentEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES132Element.OCSP_VALUES, XAdES132Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentRevocationValuesEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES132Element.REVOCATION_VALUES, XAdES132Element.OCSP_VALUES, XAdES132Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES132Element.CRL_VALUES, XAdES132Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentRevocationValuesEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES132Element.REVOCATION_VALUES, XAdES132Element.CRL_VALUES, XAdES132Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentQualifyingPropertiesPath() {
		return fromCurrentPosition(XAdES132Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public String getCurrentDescription() {
		return fromCurrentPosition(XAdES132Element.DESCRIPTION);
	}

	@Override
	public String getCurrentObjectIdentifier() {
		return fromCurrentPosition(XAdES132Element.OBJECT_IDENTIFIER);
	}

	@Override
	public String getCurrentMimeType() {
		return fromCurrentPosition(XAdES132Element.MIME_TYPE);
	}

	@Override
	public String getCurrentEncoding() {
		return fromCurrentPosition(XAdES132Element.ENCODING);
	}

	// --------------------------- Signature Policy Store

	@Override
	public String getCurrentSPDocSpecification() {
		return fromCurrentPosition(XAdES141Element.SP_DOC_SPECIFICATION);
	}

	@Override
	public String getCurrentIdentifier() {
		return fromCurrentPosition(XAdES132Element.IDENTIFIER);
	}

	@Override
	public String getCurrentSPDocSpecificationIdentifier() {
		return fromCurrentPosition(XAdES141Element.SP_DOC_SPECIFICATION, XAdES132Element.IDENTIFIER);
	}

	@Override
	public String getCurrentSPDocSpecificationDescription() {
		return fromCurrentPosition(XAdES141Element.SP_DOC_SPECIFICATION, XAdES132Element.DESCRIPTION);
	}

	@Override
	public String getCurrentDocumentationReferenceElements() {
		return fromCurrentPosition(XAdES132Element.DOCUMENTATION_REFERENCES,
				XAdES132Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public String getCurrentSPDocSpecificationDocumentationReferenceElements() {
		return fromCurrentPosition(XAdES141Element.SP_DOC_SPECIFICATION, XAdES132Element.DOCUMENTATION_REFERENCES,
				XAdES132Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public String getCurrentSignaturePolicyDocument() {
		return fromCurrentPosition(XAdES141Element.SIGNATURE_POLICY_DOCUMENT);
	}

	@Override
	public String getCurrentSigPolDocLocalURI() {
		return fromCurrentPosition(XAdES141Element.SIG_POL_DOC_LOCAL_URI);
	}

	@Override
	public XSDAbstractUtils getXSDUtils() {
		return XAdES319132Utils.getInstance();
	}

}
