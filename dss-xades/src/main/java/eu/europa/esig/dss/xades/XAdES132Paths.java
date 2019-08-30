package eu.europa.esig.dss.xades;

public class XAdES132Paths extends AbstractPaths implements XAdESPaths {

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
	public String getSigningCertificateV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNING_CERTIFICATE_V2);
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
	public String getSignaturePolicyIdentifier() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_SIGNATURE_PROPERTIES, XAdES132Element.SIGNATURE_POLICY_IDENTIFIER);
	}

	@Override
	public String getSignedDataObjectPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.SIGNED_PROPERTIES,
				XAdES132Element.SIGNED_DATA_OBJECT_PROPERTIES);
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
	public String getCompleteCertificateRefsV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2);
	}

	@Override
	public String getAttributeCertificateRefsPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_CERTIFICATE_REFS);
	}

	@Override
	public String getAttributeCertificateRefsV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2);
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
	public String getEncapsulatedAttrAuthoritiesCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTR_AUTHORITIES_CERT_VALUES, XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getEncapsulatedTimeStampValidationDataCertValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.TIMESTAMP_VALIDATION_DATA, XAdES132Element.ENCAPSULATED_X509_CERTIFICATE);
	}

	@Override
	public String getAttributeRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES132Element.ATTRIBUTE_REVOCATION_VALUES, XAdES132Element.REVOCATION_VALUES);
	}

	@Override
	public String getTimeStampValidationDataRevocationValuesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdES132Element.QUALIFYING_PROPERTIES, XAdES132Element.UNSIGNED_PROPERTIES,
				XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES, XAdES141Element.TIMESTAMP_VALIDATION_DATA, XAdES132Element.REVOCATION_VALUES);
	}

	@Override
	public String getSignatureTimestampsPath() {
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
	public String getCurrentCertRefsChildren() {
		return fromCurrentPosition(XAdES132Element.CERT_REFS, XAdES132Element.CERT);
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
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_ID);
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
	public String getCurrentSignaturePolicyDescription() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_ID, XAdES132Element.SIG_POLICY_ID, XAdES132Element.DESCRIPTION);
	}

	@Override
	public String getCurrentSignaturePolicyImplied() {
		return fromCurrentPosition(XAdES132Element.SIGNATURE_POLICY_IMPLIED);
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

}
