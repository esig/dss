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
package eu.europa.esig.dss.xades.definition.xades111;

import eu.europa.esig.dss.definition.AbstractPaths;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import eu.europa.esig.xades.XAdES111Utils;
import eu.europa.esig.xmldsig.XSDAbstractUtils;

/**
 * XAdES 1.1.1 paths
 */
public class XAdES111Paths extends AbstractPaths implements XAdESPaths {

	/** The path "./xades111:DigestMethod/xades111:Algorithm" */
	public static final String DIGEST_METHOD_ALGORITHM_PATH = fromCurrentPosition(XAdES111Element.DIGEST_METHOD, XMLDSigAttribute.ALGORITHM);

	/** The path "./xades111:DigestValue" */
	public static final String DIGEST_VALUE_PATH = fromCurrentPosition(XAdES111Element.DIGEST_VALUE);

	/** The path "./xades111:HashDataInfo/xades111:Transforms/xades111:Transform" */
	public static final String HASH_DATA_INFO_TRANSFORM_PATH = fromCurrentPosition(XAdES111Element.HASH_DATA_INFO, XAdES111Element.TRANSFORMS, XMLDSigElement.TRANSFORM);

	@Override
	public DSSNamespace getNamespace() {
		return XAdESNamespaces.XADES_111;
	}

	@Override
	public String getSignedPropertiesUri() {
		return "http://uri.etsi.org/01903/v1.1.1#SignedProperties";
	}

	@Override
	public String getCounterSignatureUri() {
		return "http://uri.etsi.org/01903#CountersignedSignature";
	}

	@Override
	public String getQualifyingPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES);
	}

	@Override
	public String getSignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES);
	}

	@Override
	public String getSignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public String getSigningTimePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_SIGNATURE_PROPERTIES, XAdES111Element.SIGNING_TIME);
	}

	@Override
	public String getSigningCertificatePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_SIGNATURE_PROPERTIES, XAdES111Element.SIGNING_CERTIFICATE, XAdES111Element.CERT);
	}

	@Override
	public String getSigningCertificateV2Path() {
		return null;
	}

	@Override
	public String getSignatureProductionPlacePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_SIGNATURE_PROPERTIES, XAdES111Element.SIGNATURE_PRODUCTION_PLACE);
	}

	@Override
	public String getSignatureProductionPlaceV2Path() {
		return null;
	}

	@Override
	public String getSignaturePolicyIdentifier() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_SIGNATURE_PROPERTIES, XAdES111Element.SIGNATURE_POLICY_IDENTIFIER);
	}

	@Override
	public String getClaimedRolePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_SIGNATURE_PROPERTIES, XAdES111Element.SIGNER_ROLE, XAdES111Element.CLAIMED_ROLES, XAdES111Element.CLAIMED_ROLE);
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
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_SIGNATURE_PROPERTIES, XAdES111Element.SIGNER_ROLE, XAdES111Element.CERTIFIED_ROLES, XAdES111Element.CERTIFIED_ROLE);
	}

	@Override
	public String getCertifiedRoleV2Path() {
		return null;
	}

	@Override
	public String getSignedDataObjectPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_DATA_OBJECT_PROPERTIES);
	}

	@Override
	public String getDataObjectFormatMimeType() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES111Element.DATA_OBJECT_FORMAT, XAdES111Element.MIME_TYPE);
	}

	@Override
	public String getDataObjectFormatObjectIdentifier() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES111Element.DATA_OBJECT_FORMAT, XAdES111Element.OBJECT_IDENTIFIER);
	}

	@Override
	public String getCommitmentTypeIndicationPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.SIGNED_PROPERTIES,
				XAdES111Element.SIGNED_DATA_OBJECT_PROPERTIES, XAdES111Element.COMMITMENT_TYPE_INDICATION);
	}

	@Override
	public String getUnsignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES);
	}

	@Override
	public String getUnsignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES);
	}

	@Override
	public String getCounterSignaturePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.COUNTER_SIGNATURE);
	}

	@Override
	public String getAttributeRevocationRefsPath() {
		return null;
	}

	@Override
	public String getCompleteRevocationRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.COMPLETE_REVOCATION_REFS);
	}

	@Override
	public String getCompleteCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.COMPLETE_CERTIFICATE_REFS);
	}

	@Override
	public String getCompleteCertificateRefsCertPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.COMPLETE_CERTIFICATE_REFS, XAdES111Element.CERT_REFS, XAdES111Element.CERT);
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
		return null;
	}

	@Override
	public String getAttributeCertificateRefsCertPath() {
		return null;
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
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.CERTIFICATE_VALUES);
	}

	@Override
	public String getRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.REVOCATION_VALUES);
	}

	@Override
	public String getEncapsulatedCertificateValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.CERTIFICATE_VALUES, XAdES111Element.ENCAPSULATED_X509_CERTIFICATE);
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
	public String getSignatureTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.SIGNATURE_TIMESTAMP);
	}

	@Override
	public String getSigAndRefsTimestampPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES111Element.QUALIFYING_PROPERTIES, XAdES111Element.UNSIGNED_PROPERTIES,
				XAdES111Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES111Element.SIG_AND_REFS_TIMESTAMP);
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
		return fromCurrentPosition(XAdES111Element.CRL_VALUES, XAdES111Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentCRLRefsChildren() {
		return fromCurrentPosition(XAdES111Element.CRL_REFS, XAdES111Element.CRL_REF);
	}

	@Override
	public String getCurrentOCSPRefsChildren() {
		return fromCurrentPosition(XAdES111Element.OCSP_REFS, XAdES111Element.OCSP_REF);
	}

	@Override
	public String getCurrentOCSPValuesChildren() {
		return fromCurrentPosition(XAdES111Element.OCSP_VALUES, XAdES111Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentOCSPRefResponderID() {
		return fromCurrentPosition(XAdES111Element.OCSP_IDENTIFIER, XAdES111Element.RESPONDER_ID);
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
		return fromCurrentPosition(XAdES111Element.OCSP_IDENTIFIER, XAdES111Element.PRODUCED_AT);
	}

	@Override
	public String getCurrentDigestAlgAndValue() {
		return fromCurrentPosition(XAdES111Element.DIGEST_ALG_AND_VALUE);
	}

	@Override
	public String getCurrentCertRefsCertChildren() {
		return fromCurrentPosition(XAdES111Element.CERT_REFS, XAdES111Element.CERT);
	}

	@Override
	public String getCurrentCertRefs141CertChildren() {
		return null;
	}

	@Override
	public String getCurrentCertChildren() {
		return fromCurrentPosition(XAdES111Element.CERT);
	}

	@Override
	public String getCurrentCertDigest() {
		return fromCurrentPosition(XAdES111Element.CERT_DIGEST);
	}

	@Override
	public String getCurrentEncapsulatedTimestamp() {
		return fromCurrentPosition(XAdES111Element.ENCAPSULATED_TIMESTAMP);
	}

	@Override
	public String getCurrentSignaturePolicyId() {
		return fromCurrentPosition(XAdES111Element.SIGNATURE_POLICY_ID, XAdES111Element.SIG_POLICY_ID, XAdES111Element.IDENTIFIER);
	}

	@Override
	public String getCurrentSignaturePolicyDigestAlgAndValue() {
		return fromCurrentPosition(XAdES111Element.SIGNATURE_POLICY_ID, XAdES111Element.SIG_POLICY_HASH);
	}

	@Override
	public String getCurrentSignaturePolicySPURI() {
		return fromCurrentPosition(XAdES111Element.SIGNATURE_POLICY_ID, XAdES111Element.SIG_POLICY_QUALIFIERS, XAdES111Element.SIG_POLICY_QUALIFIER,
				XAdES111Element.SP_URI);
	}

	@Override
	public String getCurrentSignaturePolicyDescription() {
		return fromCurrentPosition(XAdES111Element.SIGNATURE_POLICY_ID, XAdES111Element.SIG_POLICY_ID, XAdES111Element.DESCRIPTION);
	}

	@Override
	public String getCurrentSignaturePolicyDocumentationReferences() {
		return fromCurrentPosition(XAdES111Element.SIGNATURE_POLICY_ID, XAdES111Element.SIG_POLICY_ID, XAdES111Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public String getCurrentSignaturePolicyImplied() {
		return fromCurrentPosition(XAdES111Element.SIGNATURE_POLICY_IMPLIED);
	}
	
	@Override
	public String getCurrentSignaturePolicyTransforms() {
		return fromCurrentPosition(XAdES111Element.SIGNATURE_POLICY_ID, XMLDSigElement.TRANSFORMS);
	}

	@Override
	public String getCurrentIssuerSerialIssuerNamePath() {
		return fromCurrentPosition(XAdES111Element.ISSUER_SERIAL, XMLDSigElement.X509_ISSUER_NAME);
	}

	@Override
	public String getCurrentIssuerSerialSerialNumberPath() {
		return fromCurrentPosition(XAdES111Element.ISSUER_SERIAL, XMLDSigElement.X509_SERIAL_NUMBER);
	}

	@Override
	public String getCurrentIssuerSerialV2Path() {
		return null;
	}

	@Override
	public String getCurrentCommitmentIdentifierPath() {
		return fromCurrentPosition(XAdES111Element.COMMITMENT_TYPE_ID, XAdES111Element.IDENTIFIER);
	}

	@Override
	public String getCurrentCommitmentDescriptionPath() {
		return fromCurrentPosition(XAdES111Element.COMMITMENT_TYPE_ID, XAdES111Element.DESCRIPTION);
	}

	@Override
	public String getCurrentCommitmentDocumentationReferencesPath() {
		return fromCurrentPosition(XAdES111Element.COMMITMENT_TYPE_ID, XAdES111Element.DOCUMENTATION_REFERENCES);
	}

	@Override
	public String getCurrentDocumentationReference() {
		return fromCurrentPosition(XAdES111Element.DOCUMENTATION_REFERENCE);
	}

	@Override
	public String getCurrentInclude() {
		return null;
	}

	@Override
	public String getCurrentEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES111Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getCurrentCertificateValuesEncapsulatedCertificate() {
		return fromCurrentPosition(XAdES111Element.CERTIFICATE_VALUES, XAdES111Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getCurrentEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES111Element.OCSP_VALUES, XAdES111Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentRevocationValuesEncapsulatedOCSPValue() {
		return fromCurrentPosition(XAdES111Element.REVOCATION_VALUES, XAdES111Element.OCSP_VALUES, XAdES111Element.ENCAPSULATED_OCSP_VALUE);
	}

	@Override
	public String getCurrentEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES111Element.CRL_VALUES, XAdES111Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentRevocationValuesEncapsulatedCRLValue() {
		return fromCurrentPosition(XAdES111Element.REVOCATION_VALUES, XAdES111Element.CRL_VALUES, XAdES111Element.ENCAPSULATED_CRL_VALUE);
	}

	@Override
	public String getCurrentQualifyingPropertiesPath() {
		return fromCurrentPosition(XAdES111Element.QUALIFYING_PROPERTIES);
	}

	// --------------------------- Signature Policy Store

	@Override
	public String getCurrentSPDocSpecificationIdentifier() {
		return null;
	}

	@Override
	public String getCurrentSPDocSpecificationDescription() {
		return null;
	}

	@Override
	public String getCurrentSPDocSpecificationDocumentReferenceElements() {
		return null;
	}

	@Override
	public String getCurrentSignaturePolicyDocument() {
		return null;
	}

	@Override
	public XSDAbstractUtils getXSDUtils() {
		return XAdES111Utils.getInstance();
	}

}
