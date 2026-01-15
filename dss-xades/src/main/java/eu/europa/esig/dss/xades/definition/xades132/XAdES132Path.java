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
package eu.europa.esig.dss.xades.definition.xades132;

import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.definition.xadesen.XAdESEvidencerecordNamespaceElement;
import eu.europa.esig.dss.xml.common.definition.AbstractPath;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;

/**
 * XAdES 1.3.2 paths
 */
public class XAdES132Path extends AbstractPath implements XAdESPath {

	private static final long serialVersionUID = 1878591854613359863L;

	/** Gets all signatures without counter signatures */
	public static final XPathQuery ALL_SIGNATURE_WITH_NO_COUNTERSIGNATURE_AS_PARENT_PATH =
			allNotParent(XMLDSigElement.SIGNATURE, XAdES132Element.COUNTER_SIGNATURE);

	/** Gets all encapsulated time-stamp token elements */
	public static final XPathQuery ALL_ENCAPSULATED_TIMESTAMP_PARENT_PATH = all(XAdES132Element.ENCAPSULATED_TIMESTAMP);

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
	public XPathQuery getQualifyingPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public XPathQuery getSignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES);
	}

	@Override
	public XPathQuery getSignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public XPathQuery getSigningTimePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_TIME);
	}

	@Override
	public XPathQuery getSigningCertificatePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE);
	}

	@Override
	public XPathQuery getSigningCertificateChildren() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE, XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getSigningCertificateV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE_V2);
	}

	@Override
	public XPathQuery getSigningCertificateV2Children() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE_V2, XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getSignatureProductionPlacePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_PRODUCTION_PLACE);
	}

	@Override
	public XPathQuery getSignatureProductionPlaceV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_PRODUCTION_PLACE_V2);
	}

	@Override
	public XPathQuery getSignaturePolicyIdentifierPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_POLICY_IDENTIFIER);
	}

	@Override
	public XPathQuery getSignerRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE);
	}

	@Override
	public XPathQuery getSignerRoleV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE_V2);
	}

	@Override
	public XPathQuery getClaimedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE, XAdES132Element.CLAIMED_ROLES, XAdES132Element.CLAIMED_ROLE);
	}

	@Override
	public XPathQuery getClaimedRoleV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE_V2, XAdES132Element.CLAIMED_ROLES, XAdES132Element.CLAIMED_ROLE);
	}
	
	@Override
	public XPathQuery getSignedAssertionPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE_V2, XAdES132Element.SIGNED_ASSERTIONS, XAdES132Element.SIGNED_ASSERTION);
	}

	@Override
	public XPathQuery getCertifiedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE, XAdES132Element.CERTIFIED_ROLES, XAdES132Element.CERTIFIED_ROLE);
	}

	@Override
	public XPathQuery getCertifiedRoleV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNER_ROLE_V2, XAdES132Element.CERTIFIED_ROLES_V2,
				XAdES132Element.CERTIFIED_ROLE);
	}

	@Override
	public XPathQuery getSignedDataObjectPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES);
	}

	@Override
	public XPathQuery getAllDataObjectsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.ALL_DATA_OBJECTS_TIMESTAMP);
	}

	@Override
	public XPathQuery getIndividualDataObjectsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
	}

	@Override
	public XPathQuery getDataObjectFormat() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.DATA_OBJECT_FORMAT);
	}

	@Override
	public XPathQuery getDataObjectFormatMimeType() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.DATA_OBJECT_FORMAT, XAdES132Element.MIME_TYPE);
	}

	@Override
	public XPathQuery getDataObjectFormatObjectIdentifier() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.DATA_OBJECT_FORMAT, XAdES132Element.OBJECT_IDENTIFIER);
	}

	@Override
	public XPathQuery getCommitmentTypeIndicationPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES132Element.COMMITMENT_TYPE_INDICATION);
	}

	@Override
	public XPathQuery getUnsignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES);
	}

	@Override
	public XPathQuery getUnsignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public XPathQuery getCounterSignaturePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.COUNTER_SIGNATURE);
	}

	@Override
	public XPathQuery getAttributeRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_REVOCATION_REFS);
	}

	@Override
	public XPathQuery getCompleteRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.COMPLETE_REVOCATION_REFS);
	}

	@Override
	public XPathQuery getCompleteCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.COMPLETE_CERTIFICATE_REFS);
	}

	@Override
	public XPathQuery getCompleteCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.COMPLETE_CERTIFICATE_REFS, XAdES132Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getCompleteCertificateRefsV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2);
	}

	@Override
	public XPathQuery getCompleteCertificateRefsV2CertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2, XAdES141Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getAttributeCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_CERTIFICATE_REFS);
	}

	@Override
	public XPathQuery getAttributeCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_CERTIFICATE_REFS, XAdES132Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getAttributeCertificateRefsV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2);
	}

	@Override
	public XPathQuery getAttributeCertificateRefsV2CertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2, XAdES141Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.CERTIFICATE_VALUES);
	}

	@Override
	public XPathQuery getRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.REVOCATION_VALUES);
	}

	@Override
	public XPathQuery getEncapsulatedCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.CERTIFICATE_VALUES, XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getAttrAuthoritiesCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTR_AUTHORITIES_CERT_VALUES);
	}

	@Override
	public XPathQuery getEncapsulatedAttrAuthoritiesCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTR_AUTHORITIES_CERT_VALUES, XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getEncapsulatedTimeStampValidationDataCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.TIMESTAMP_VALIDATION_DATA, XAdES132Element.CERTIFICATE_VALUES,
				XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getAttributeRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_REVOCATION_VALUES);
	}

	@Override
	public XPathQuery getTimeStampValidationDataRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.TIMESTAMP_VALIDATION_DATA, XAdES132Element.REVOCATION_VALUES);
	}

	@Override
	public XPathQuery getAnyValidationDataPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ANY_VALIDATION_DATA);
	}

	@Override
	public XPathQuery getEncapsulatedAnyValidationDataCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ANY_VALIDATION_DATA, XAdES132Element.CERTIFICATE_VALUES,
				XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getAnyValidationDataRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ANY_VALIDATION_DATA, XAdES132Element.REVOCATION_VALUES);
	}

	@Override
	public XPathQuery getSignatureTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_TIMESTAMP);
	}

	@Override
	public XPathQuery getSigAndRefsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIG_AND_REFS_TIMESTAMP);
	}

	@Override
	public XPathQuery getSigAndRefsTimestampV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.SIG_AND_REFS_TIMESTAMP_V2);
	}

	@Override
	public XPathQuery getRefsOnlyTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.REFS_ONLY_TIMESTAMP);
	}

	@Override
	public XPathQuery getRefsOnlyTimestampV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.REFS_ONLY_TIMESTAMP_V2);
	}

	@Override
	public XPathQuery getArchiveTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ARCHIVE_TIMESTAMP);
	}

	@Override
	public XPathQuery getTimestampValidationDataPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.TIMESTAMP_VALIDATION_DATA);
	}

	@Override
	public XPathQuery getSignaturePolicyStorePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES,
				XAdES132Element.UNSIGNED_PROPERTIES, XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES,
				XAdES141Element.SIGNATURE_POLICY_STORE);
	}

	@Override
	public XPathQuery getSealingEvidenceRecordsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES,
				XAdES132Element.UNSIGNED_PROPERTIES, XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES,
				XAdESEvidencerecordNamespaceElement.SEALING_EVIDENCE_RECORDS);
	}

	// ------------------------------------------------

	@Override
	public XPathQuery getCurrentCRLValuesChildren() {
		return fromCurrentPosition(XAdES132Element.CRL_VALUES, XAdES132Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public XPathQuery getCurrentCRLRefsChildren() {
		return fromCurrentPosition(XAdES132Element.CRL_REFS, XAdES132Element.CRL_REF);
	}

	@Override
	public XPathQuery getCurrentCRLRefCRLIdentifier() {
		return fromCurrentPosition(XAdES132Element.CRL_IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentCRLRefCRLIdentifierIssuer() {
		return fromCurrentPosition(XAdES132Element.CRL_IDENTIFIER, XAdES132Element.ISSUER);
	}

	@Override
	public XPathQuery getCurrentCRLRefCRLIdentifierIssueTime() {
		return fromCurrentPosition(XAdES132Element.CRL_IDENTIFIER, XAdES132Element.ISSUE_TIME);
	}

	@Override
	public XPathQuery getCurrentCRLRefCRLIdentifierNumber() {
		return fromCurrentPosition(XAdES132Element.CRL_IDENTIFIER, XAdES132Element.NUMBER);
	}

	@Override
	public XPathQuery getCurrentOCSPRefsChildren() {
		return fromCurrentPosition(XAdES132Element.OCSP_REFS, XAdES132Element.OCSP_REF);
	}

	@Override
	public XPathQuery getCurrentOCSPValuesChildren() {
		return fromCurrentPosition(XAdES132Element.OCSP_VALUES, XAdES132Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public XPathQuery getCurrentOCSPRefResponderID() {
		return fromCurrentPosition(XAdES132Element.OCSP_IDENTIFIER, XAdES132Element.RESPONDER_ID);
	}

	@Override
	public XPathQuery getCurrentOCSPRefResponderIDByName() {
		return fromCurrentPosition(XAdES132Element.OCSP_IDENTIFIER, XAdES132Element.RESPONDER_ID, XAdES132Element.BY_NAME);
	}

	@Override
	public XPathQuery getCurrentOCSPRefResponderIDByKey() {
		return fromCurrentPosition(XAdES132Element.OCSP_IDENTIFIER, XAdES132Element.RESPONDER_ID, XAdES132Element.BY_KEY);
	}

	@Override
	public XPathQuery getCurrentOCSPRefProducedAt() {
		return fromCurrentPosition(XAdES132Element.OCSP_IDENTIFIER, XAdES132Element.PRODUCED_AT);
	}

	@Override
	public XPathQuery getCurrentDigestAlgAndValue() {
		return fromCurrentPosition(XAdES132Element.DIGEST_ALG_AND_VALUE);
	}

	@Override
	public XPathQuery getCurrentCertRefsCertChildren() {
		return fromCurrentPosition(XAdES132Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getCurrentCertRefs141CertChildren() {
		return fromCurrentPosition(XAdES141Element.CERT_REFS, XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getCurrentCertChildren() {
		return fromCurrentPosition(XAdES132Element.CERT);
	}

	@Override
	public XPathQuery getCurrentCertDigest() {
		return fromCurrentPosition(XAdES132Element.CERT_DIGEST);
	}

	@Override
	public XPathQuery getCurrentEncapsulatedTimestamp() {
		return fromCurrentPosition(XAdES132Element.ENCAPSULATED_TIMESTAMP);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyId() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_ID, XAdES132Element.IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyDigestAlgAndValue() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_HASH);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicySPURI() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS, XAdES132Element.SIG_POLICY_QUALIFIER,
				XAdES132Element.SP_URI);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicySPUserNotice() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS, XAdES132Element.SIG_POLICY_QUALIFIER,
				XAdES132Element.SP_USER_NOTICE);
	}

	@Override
	public XPathQuery getCurrentSPUserNoticeNoticeRefOrganization() {
		return fromCurrentPosition(XAdES132Element.NOTICE_REF, XAdES132Element.ORGANIZATION);
	}

	@Override
	public XPathQuery getCurrentSPUserNoticeNoticeRefNoticeNumbers() {
		return fromCurrentPosition(XAdES132Element.NOTICE_REF, XAdES132Element.NOTICE_NUMBERS);
	}

	@Override
	public XPathQuery getCurrentSPUserNoticeExplicitText() {
		return fromCurrentPosition(XAdES132Element.EXPLICIT_TEXT);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicySPDocSpecification() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS,
				XAdES132Element.SIG_POLICY_QUALIFIER, XAdES141Element.SP_DOC_SPECIFICATION);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicySPDocSpecificationIdentifier() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS,
				XAdES132Element.SIG_POLICY_QUALIFIER, XAdES141Element.SP_DOC_SPECIFICATION, XAdES132Element.IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyDescription() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_ID, XAdES132Element.DESCRIPTION);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyDocumentationReferences() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_ID, XAdES132Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyImplied() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_IMPLIED);
	}
	
	@Override
	public XPathQuery getCurrentSignaturePolicyTransforms() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XMLDSigElement.TRANSFORMS);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyQualifiers() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_QUALIFIERS);
	}

	@Override
	public XPathQuery getCurrentIssuerSerialIssuerNamePath() {
		return fromCurrentPosition(XAdES132Element.ISSUER_SERIAL, XMLDSigElement.X509_ISSUER_NAME);
	}

	@Override
	public XPathQuery getCurrentIssuerSerialSerialNumberPath() {
		return fromCurrentPosition(XAdES132Element.ISSUER_SERIAL, XMLDSigElement.X509_SERIAL_NUMBER);
	}

	@Override
	public XPathQuery getCurrentIssuerSerialV2Path() {
		return fromCurrentPosition(XAdES132Element.ISSUER_SERIAL_V2);
	}

	@Override
	public XPathQuery getCurrentCommitmentIdentifierPath() {
		return fromCurrentPosition(XAdES132Element.COMMITMENT_TYPE_ID, XAdES132Element.IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentCommitmentDescriptionPath() {
		return fromCurrentPosition(XAdES132Element.COMMITMENT_TYPE_ID, XAdES132Element.DESCRIPTION);
	}

	@Override
	public XPathQuery getCurrentCommitmentDocumentationReferencesPath() {
		return fromCurrentPosition(XAdES132Element.COMMITMENT_TYPE_ID, XAdES132Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public XPathQuery getCurrentDocumentationReference() {
		return fromCurrentPosition(XAdES132Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public XPathQuery getCurrentCommitmentObjectReferencesPath() {
		return fromCurrentPosition(XAdES132Element.OBJECT_REFERENCE);
	}

	@Override
	public XPathQuery getCurrentCommitmentAllSignedDataObjectsPath() {
		return fromCurrentPosition(XAdES132Element.ALL_SIGNED_DATA_OBJECTS);
	}

	@Override
	public XPathQuery getCurrentInclude() {
		return fromCurrentPosition(XAdES132Element.INCLUDE);
	}

	@Override
	public XPathQuery getCurrentEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getCurrentCertificateValuesEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES132Element.CERTIFICATE_VALUES, XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public XPathQuery getCurrentEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES132Element.OCSP_VALUES, XAdES132Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public XPathQuery getCurrentRevocationValuesEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES132Element.REVOCATION_VALUES, XAdES132Element.OCSP_VALUES, XAdES132Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public XPathQuery getCurrentEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES132Element.CRL_VALUES, XAdES132Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public XPathQuery getCurrentRevocationValuesEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES132Element.REVOCATION_VALUES, XAdES132Element.CRL_VALUES, XAdES132Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public XPathQuery getCurrentQualifyingPropertiesPath() {
		return fromCurrentPosition(XAdES132Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public XPathQuery getCurrentDescription() {
		return fromCurrentPosition(XAdES132Element.DESCRIPTION);
	}

	@Override
	public XPathQuery getCurrentObjectIdentifier() {
		return fromCurrentPosition(XAdES132Element.OBJECT_IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentMimeType() {
		return fromCurrentPosition(XAdES132Element.MIME_TYPE);
	}

	@Override
	public XPathQuery getCurrentEncoding() {
		return fromCurrentPosition(XAdES132Element.ENCODING);
	}

	// --------------------------- Signature Policy Store

	@Override
	public XPathQuery getCurrentSPDocSpecification() {
		return fromCurrentPosition(XAdES141Element.SP_DOC_SPECIFICATION);
	}

	@Override
	public XPathQuery getCurrentIdentifier() {
		return fromCurrentPosition(XAdES132Element.IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentSPDocSpecificationIdentifier() {
		return fromCurrentPosition(XAdES141Element.SP_DOC_SPECIFICATION, XAdES132Element.IDENTIFIER);
	}

	@Override
	public XPathQuery getCurrentSPDocSpecificationDescription() {
		return fromCurrentPosition(XAdES141Element.SP_DOC_SPECIFICATION, XAdES132Element.DESCRIPTION);
	}

	@Override
	public XPathQuery getCurrentDocumentationReferenceElements() {
		return fromCurrentPosition(XAdES132Element.DOCUMENTATION_REFERENCES,
				XAdES132Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public XPathQuery getCurrentSPDocSpecificationDocumentationReferenceElements() {
		return fromCurrentPosition(XAdES141Element.SP_DOC_SPECIFICATION, XAdES132Element.DOCUMENTATION_REFERENCES,
				XAdES132Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public XPathQuery getCurrentSignaturePolicyDocument() {
		return fromCurrentPosition(XAdES141Element.SIGNATURE_POLICY_DOCUMENT);
	}

	@Override
	public XPathQuery getCurrentSigPolDocLocalURI() {
		return fromCurrentPosition(XAdES141Element.SIG_POL_DOC_LOCAL_URI);
	}

}
