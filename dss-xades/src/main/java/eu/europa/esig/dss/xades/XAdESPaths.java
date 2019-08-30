package eu.europa.esig.dss.xades;

public interface XAdESPaths {

	String getSignedPropertiesUri();

	String getCounterSignatureUri();

	// ----------------------- From Object

	String getQualifyingPropertiesPath();

	String getSignedPropertiesPath();

	String getSignedSignaturePropertiesPath();

	String getSigningTimePath();

	String getSigningCertificatePath();

	String getSigningCertificateV2Path();

	String getSignatureProductionPlacePath();

	String getSignatureProductionPlaceV2Path();

	String getSignedDataObjectPropertiesPath();

	String getDataObjectFormatMimeType();

	String getDataObjectFormatObjectIdentifier();

	String getCommitmentTypeIndicationPath();

	String getUnsignedPropertiesPath();

	String getUnsignedSignaturePropertiesPath();

	String getCounterSignaturePath();

	String getAttributeRevocationRefsPath();

	String getCompleteRevocationRefsPath();

	String getCompleteCertificateRefsPath();

	String getCompleteCertificateRefsV2Path();

	String getAttributeCertificateRefsPath();

	String getAttributeCertificateRefsV2Path();

	String getCertificateValuesPath();

	String getRevocationValuesPath();

	String getAttributeRevocationValuesPath();
	
	String getTimeStampValidationDataRevocationValuesPath();

	String getSignatureTimestampsPath();

	String getSigAndRefsTimestampPath();

	String getSigAndRefsTimestampV2Path();

	String getSignaturePolicyIdentifier();

	String getEncapsulatedCertificateValuesPath();

	String getEncapsulatedAttrAuthoritiesCertValuesPath();

	String getEncapsulatedTimeStampValidationDataCertValuesPath();

	// ----------------

	String getCurrentCRLValuesChildren();

	String getCurrentCRLRefsChildren();

	String getCurrentOCSPValuesChildren();

	String getCurrentOCSPRefsChildren();

	String getCurrentOCSPRefResponderID();

	String getCurrentOCSPRefResponderIDByName();

	String getCurrentOCSPRefResponderIDByKey();

	String getCurrentOCSPRefProducedAt();

	String getCurrentDigestAlgAndValue();

	String getCurrentCertRefsChildren();

	String getCurrentCertDigest();

	String getCurrentEncapsulatedTimestamp();
	
	String getCurrentIssuerSerialIssuerNamePath();

	String getCurrentIssuerSerialSerialNumberPath();

	String getCurrentIssuerSerialV2Path();

	// --------------------------- Policy

	String getCurrentSignaturePolicyId();

	String getCurrentSignaturePolicyDigestAlgAndValue();

	String getCurrentSignaturePolicySPURI();

	String getCurrentSignaturePolicyDescription();

	String getCurrentSignaturePolicyImplied();

}
