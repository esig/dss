package eu.europa.esig.dss.validation.executor;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.xml.bind.JAXBElement;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCertificateChain;
import eu.europa.esig.dss.jaxb.detailedreport.XmlChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCryptographicInformation;
import eu.europa.esig.dss.jaxb.detailedreport.XmlProofOfExistence;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRevocationInformation;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanToken;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignerData;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateOriginType;
import eu.europa.esig.dss.validation.CertificateRefOriginType;
import eu.europa.esig.dss.validation.DigestMatcherType;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.XmlCertificateSourceType;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.XmlRevocationRefOrigin;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.BasicBuildingBlockDefinition;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.wrapper.AbstractTokenProxy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.dss.x509.TimestampLocation;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.jaxb.validationreport.AttributeBaseType;
import eu.europa.esig.jaxb.validationreport.CertificateChainType;
import eu.europa.esig.jaxb.validationreport.ConstraintStatusType;
import eu.europa.esig.jaxb.validationreport.CryptoInformationType;
import eu.europa.esig.jaxb.validationreport.IndividualValidationConstraintReportType;
import eu.europa.esig.jaxb.validationreport.ObjectFactory;
import eu.europa.esig.jaxb.validationreport.POEProvisioningType;
import eu.europa.esig.jaxb.validationreport.POEType;
import eu.europa.esig.jaxb.validationreport.RevocationStatusInformationType;
import eu.europa.esig.jaxb.validationreport.SACRLIDType;
import eu.europa.esig.jaxb.validationreport.SACertIDListType;
import eu.europa.esig.jaxb.validationreport.SACertIDType;
import eu.europa.esig.jaxb.validationreport.SACommitmentTypeIndicationType;
import eu.europa.esig.jaxb.validationreport.SAContactInfoType;
import eu.europa.esig.jaxb.validationreport.SACounterSignatureType;
import eu.europa.esig.jaxb.validationreport.SADSSType;
import eu.europa.esig.jaxb.validationreport.SADataObjectFormatType;
import eu.europa.esig.jaxb.validationreport.SAFilterType;
import eu.europa.esig.jaxb.validationreport.SAMessageDigestType;
import eu.europa.esig.jaxb.validationreport.SANameType;
import eu.europa.esig.jaxb.validationreport.SAOCSPIDType;
import eu.europa.esig.jaxb.validationreport.SAOneSignerRoleType;
import eu.europa.esig.jaxb.validationreport.SAReasonType;
import eu.europa.esig.jaxb.validationreport.SARevIDListType;
import eu.europa.esig.jaxb.validationreport.SASigPolicyIdentifierType;
import eu.europa.esig.jaxb.validationreport.SASignatureProductionPlaceType;
import eu.europa.esig.jaxb.validationreport.SASignerRoleType;
import eu.europa.esig.jaxb.validationreport.SASigningTimeType;
import eu.europa.esig.jaxb.validationreport.SASubFilterType;
import eu.europa.esig.jaxb.validationreport.SATimestampType;
import eu.europa.esig.jaxb.validationreport.SAVRIType;
import eu.europa.esig.jaxb.validationreport.SignatureAttributesType;
import eu.europa.esig.jaxb.validationreport.SignatureIdentifierType;
import eu.europa.esig.jaxb.validationreport.SignatureReferenceType;
import eu.europa.esig.jaxb.validationreport.SignatureValidationProcessType;
import eu.europa.esig.jaxb.validationreport.SignatureValidationReportType;
import eu.europa.esig.jaxb.validationreport.SignerInformationType;
import eu.europa.esig.jaxb.validationreport.SignersDocumentType;
import eu.europa.esig.jaxb.validationreport.VOReferenceType;
import eu.europa.esig.jaxb.validationreport.ValidationConstraintsEvaluationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectListType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectRepresentationType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectType;
import eu.europa.esig.jaxb.validationreport.ValidationReportDataType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationStatusType;
import eu.europa.esig.jaxb.validationreport.ValidationTimeInfoType;
import eu.europa.esig.jaxb.validationreport.enums.ConstraintStatus;
import eu.europa.esig.jaxb.validationreport.enums.EndorsementType;
import eu.europa.esig.jaxb.validationreport.enums.MainIndication;
import eu.europa.esig.jaxb.validationreport.enums.ObjectType;
import eu.europa.esig.jaxb.validationreport.enums.RevocationReason;
import eu.europa.esig.jaxb.validationreport.enums.SignatureValidationProcessID;
import eu.europa.esig.jaxb.validationreport.enums.TypeOfProof;
import eu.europa.esig.jaxb.xades132.DigestAlgAndValueType;
import eu.europa.esig.jaxb.xmldsig.DigestMethodType;
import eu.europa.esig.jaxb.xmldsig.SignatureValueType;

public class ETSIValidationReportBuilder {

	private final ObjectFactory objectFactory = new ObjectFactory();
	private final Date currentTime;
	private final ValidationPolicy policy;
	private final DiagnosticData diagnosticData;
	private final DetailedReport detailedReport;

	public ETSIValidationReportBuilder(Date currentTime, ValidationPolicy policy, DiagnosticData diagnosticData, DetailedReport detailedReport) {
		this.currentTime = currentTime;
		this.policy = policy;
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
	}

	public ValidationReportType build() {
		ValidationReportType result = objectFactory.createValidationReportType();

		// iterate over the complete list of signatures, including counter signatures
		for (SignatureWrapper sigWrapper : diagnosticData.getSignatures()) {
			result.getSignatureValidationReport().add(getSignatureValidationReport(sigWrapper));
		}
		result.setSignatureValidationObjects(getSignatureValidationObjects());

		return result;
	}

	private SignatureValidationReportType getSignatureValidationReport(SignatureWrapper sigWrapper) {
		SignatureValidationReportType signatureValidationReport = objectFactory.createSignatureValidationReportType();
		signatureValidationReport.setSignatureIdentifier(getSignatureIdentifier(sigWrapper));
		getSignersDocuments(signatureValidationReport, sigWrapper);
		signatureValidationReport.setSignatureAttributes(getSignatureAttributes(sigWrapper));
		signatureValidationReport.setSignerInformation(getSignerInformation(sigWrapper));
		signatureValidationReport.setSignatureValidationProcess(getSignatureValidationProcess(sigWrapper));
		signatureValidationReport.setSignatureValidationStatus(getSignatureValidationStatus(sigWrapper));
		signatureValidationReport.setValidationTimeInfo(getValidationTimeInfo(sigWrapper));
		signatureValidationReport.setValidationConstraintsEvaluationReport(getValidationConstraintsEvaluationReport(sigWrapper));
		return signatureValidationReport;
	}

	private ValidationConstraintsEvaluationReportType getValidationConstraintsEvaluationReport(SignatureWrapper sigWrapper) {
		ValidationConstraintsEvaluationReportType validationConstraintsEvaluationReport = objectFactory.createValidationConstraintsEvaluationReportType();
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(sigWrapper.getId());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.FORMAT_CHECKING, signatureBBB.getFC());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.IDENTIFICATION_OF_THE_SIGNING_CERTIFICATE, signatureBBB.getISC());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.VALIDATION_CONTEXT_INITIALIZATION, signatureBBB.getVCI());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.CRYPTOGRAPHIC_VERIFICATION, signatureBBB.getCV());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.SIGNATURE_ACCEPTANCE_VALIDATION, signatureBBB.getSAV());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.X509_CERTIFICATE_VALIDATION, signatureBBB.getXCV());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.PAST_SIGNATURE_VALIDATION, signatureBBB.getPSV());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.PAST_CERTIFICATE_VALIDATION, signatureBBB.getPCV());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.VALIDATION_TIME_SLIDING, signatureBBB.getVTS());
		return validationConstraintsEvaluationReport;
	}

	private void addBBB(ValidationConstraintsEvaluationReportType validationConstraintsEvaluationReport, BasicBuildingBlockDefinition bbbUri,
			XmlConstraintsConclusion constraintConclusion) {
		if (constraintConclusion != null) {
			validationConstraintsEvaluationReport.getValidationConstraint()
					.add(getIndividualValidationConstraintReport(bbbUri, constraintConclusion, applied()));
		} else {
			validationConstraintsEvaluationReport.getValidationConstraint()
					.add(getIndividualValidationConstraintReport(bbbUri, constraintConclusion, disabled()));
		}
	}

	private IndividualValidationConstraintReportType getIndividualValidationConstraintReport(BasicBuildingBlockDefinition bbbUri,
			XmlConstraintsConclusion constraintConclusion,
			ConstraintStatusType constraintStatusType) {
		IndividualValidationConstraintReportType validationConstraint = objectFactory.createIndividualValidationConstraintReportType();
		validationConstraint.setValidationConstraintIdentifier(bbbUri.getUri());
		validationConstraint.setConstraintStatus(constraintStatusType);
		if (constraintConclusion != null) {
			validationConstraint.setValidationStatus(getValidationStatus(constraintConclusion.getConclusion()));
		}
		return validationConstraint;
	}

	private ConstraintStatusType applied() {
		return constraintStatus(ConstraintStatus.APPLIED);
	}

	private ConstraintStatusType disabled() {
		return constraintStatus(ConstraintStatus.DISABLED);
	}

	private ConstraintStatusType constraintStatus(ConstraintStatus status) {
		ConstraintStatusType constraintStatus = objectFactory.createConstraintStatusType();
		constraintStatus.setStatus(status);
		return constraintStatus;
	}

	private SignatureValidationReportType getValidationReport(AbstractTokenProxy token) {
		SignatureValidationReportType signatureValidationReport = objectFactory.createSignatureValidationReportType();
		signatureValidationReport.setSignerInformation(getSignerInformation(token));
		signatureValidationReport.setSignatureValidationStatus(getValidationStatus(token));
		return signatureValidationReport;
	}

	private ValidationTimeInfoType getValidationTimeInfo(SignatureWrapper sigWrapper) {
		ValidationTimeInfoType validationTimeInfoType = objectFactory.createValidationTimeInfoType();
		validationTimeInfoType.setValidationTime(currentTime);

		XmlProofOfExistence proofOfExistence = detailedReport.getBestProofOfExistence(sigWrapper.getId());
		POEType poeType = new POEType();
		poeType.setPOETime(proofOfExistence.getTime());
		poeType.setTypeOfProof(TypeOfProof.VALIDATION);

		String timestampId = proofOfExistence.getTimestampId();
		if (Utils.isStringNotEmpty(timestampId)) {
			poeType.setPOEObject(getVOReference(timestampId));
		}
		validationTimeInfoType.setBestSignatureTime(poeType);
		return validationTimeInfoType;
	}

	private SignerInformationType getSignerInformation(AbstractTokenProxy token) {
		CertificateWrapper signingCert = token.getSigningCertificate();
		if (signingCert == null) {
			return null;
		}
		SignerInformationType signerInfo = objectFactory.createSignerInformationType();
		signerInfo.setPseudonym(isUsePseudo(token));
		signerInfo.setSigner(signingCert.getReadableCertificateName());
		signerInfo.setSignerCertificate(getVOReference(signingCert.getId()));
		return signerInfo;
	}

	private Boolean isUsePseudo(AbstractTokenProxy token) {
		XmlSubXCV signingCertificateXCV = detailedReport.getSigningCertificate(token.getId());
		if (signingCertificateXCV != null) {
			List<XmlConstraint> constraints = signingCertificateXCV.getConstraint();
			for (XmlConstraint xmlConstraint : constraints) {
				if (MessageTag.BBB_XCV_PSEUDO_USE.name().equals(xmlConstraint.getName().getNameId())) {
					XmlStatus status = xmlConstraint.getStatus();
					return (XmlStatus.OK != status) && (XmlStatus.IGNORED != status);
				}
			}
		}
		return null;
	}

	private VOReferenceType getVOReference(String id) {
		return getVOReference(Arrays.asList(id));
	}

	private VOReferenceType getVOReference(List<String> ids) {
		VOReferenceType voRef = objectFactory.createVOReferenceType();
		for (String id : ids) {
			ValidationObjectType validationObject = objectFactory.createValidationObjectType();
			validationObject.setId(id);
			voRef.getVOReference().add(validationObject);
		}
		return voRef;
	}

	private SignatureValidationProcessType getSignatureValidationProcess(SignatureWrapper sigWrapper) {
		SignatureValidationProcessType validationProcess = objectFactory.createSignatureValidationProcessType();
		validationProcess.setSignatureValidationProcessID(getCurrentProcessId(sigWrapper));
		return validationProcess;
	}

	private SignatureValidationProcessID getCurrentProcessId(SignatureWrapper sigWrapper) {
		SignatureValidationProcessID processId = SignatureValidationProcessID.BASIC;
		Indication indicationLTA = detailedReport.getArchiveDataValidationIndication(sigWrapper.getId());
		Indication indicationLTVM = detailedReport.getLongTermValidationIndication(sigWrapper.getId());
		if (indicationLTA != null) {
			processId = SignatureValidationProcessID.LTA;
		} else if (indicationLTVM != null) {
			processId = SignatureValidationProcessID.LTVM;
		}
		return processId;
	}

	private ValidationObjectListType getSignatureValidationObjects() {
		ValidationObjectListType validationObjectListType = objectFactory.createValidationObjectListType();
		
		POEExtraction poeExtraction = new POEExtraction();
		poeExtraction.collectAllPOE(diagnosticData);

		for (CertificateWrapper certificate : diagnosticData.getUsedCertificates()) {
			addCertificate(validationObjectListType, certificate, poeExtraction);
		}
		
		for (XmlOrphanToken orphanCertificate : diagnosticData.getAllOrphanCertificates()) {
			addOrphanCertificate(validationObjectListType, orphanCertificate, poeExtraction);
		}

		for (RevocationWrapper revocationData : diagnosticData.getAllRevocationData()) {
			addRevocationData(validationObjectListType, revocationData, poeExtraction);
		}
		
		for (XmlOrphanRevocation orphanRevocation : diagnosticData.getAllOrphanRevocations()) {
			addOrphanRevocation(validationObjectListType, orphanRevocation, poeExtraction);
		}

		for (TimestampWrapper timestamp : diagnosticData.getTimestampSet()) {
			addTimestamp(validationObjectListType, timestamp);
		}
		
		for (XmlSignerData signedData : diagnosticData.getOriginalSignerDocuments()) {
			addSignerData(validationObjectListType, signedData, poeExtraction);
		}

		return validationObjectListType;
	}

	private void addCertificate(ValidationObjectListType validationObjectListType, CertificateWrapper certificate, POEExtraction poeExtraction) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(certificate.getId());
		validationObject.setObjectType(ObjectType.CERTIFICATE);
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		if (Utils.isArrayNotEmpty(certificate.getBinaries())) {
			representation.setBase64(certificate.getBinaries());
		} else {
			representation.setDigestAlgAndValue(getDigestAlgAndValueType(certificate.getDigestAlgoAndValue()));
		}
		validationObject.setValidationObject(representation);
		validationObject.setPOE(getPOE(certificate.getId(), poeExtraction));
		validationObjectListType.getValidationObject().add(validationObject);
	}
	
	private DigestAlgAndValueType getDigestAlgAndValueType(XmlDigestAlgoAndValue xmlDigestAlgoAndValue) {
		return getDigestAlgAndValueType(xmlDigestAlgoAndValue.getDigestMethod(), xmlDigestAlgoAndValue.getDigestValue());
	}
	
	private DigestAlgAndValueType getDigestAlgAndValueType(String digestMethod, byte[] digestValue) {
		DigestAlgAndValueType digestAlgAndValueType = new DigestAlgAndValueType();
		DigestMethodType digestMethodType = new DigestMethodType();
		digestMethodType.setAlgorithm(DigestAlgorithm.isSupportedAlgorithm(digestMethod) ? 
				DigestAlgorithm.forName(digestMethod).getXmlId() : "?");
		digestAlgAndValueType.setDigestMethod(digestMethodType);
		digestAlgAndValueType.setDigestValue(digestValue);
		return digestAlgAndValueType;
	}
	
	private POEType getPOE(String tokenId, POEExtraction poeExtraction) {
		POEType poeType = objectFactory.createPOEType();
		if (poeExtraction.isPOEExists(tokenId, currentTime)) {
			XmlProofOfExistence lowestPOE = poeExtraction.getLowestPOE(tokenId, currentTime);
			poeType.setPOETime(lowestPOE.getTime());
			poeType.setPOEObject(getVOReference(lowestPOE.getTimestampId()));
		} else {
			poeType.setPOETime(currentTime);
		}
		poeType.setTypeOfProof(TypeOfProof.VALIDATION);
		return poeType;
	}

	private void addTimestamp(ValidationObjectListType validationObjectListType, TimestampWrapper timestamp) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(timestamp.getId());
		validationObject.setObjectType(ObjectType.TIMESTAMP);
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		if (Utils.isArrayNotEmpty(timestamp.getBinaries())) {
			representation.setBase64(timestamp.getBinaries());
		} else {
			representation.setDigestAlgAndValue(getDigestAlgAndValueType(timestamp.getDigestAlgoAndValue()));
		}
		validationObject.setValidationObject(representation);
		validationObject.setPOEProvisioning(getPOEProvisioningType(timestamp));
		validationObject.setValidationReport(getValidationReport(timestamp));
		validationObjectListType.getValidationObject().add(validationObject);
	}

	private POEProvisioningType getPOEProvisioningType(TimestampWrapper timestamp) {
		POEProvisioningType poeProvisioning = objectFactory.createPOEProvisioningType();
		poeProvisioning.setPOETime(timestamp.getProductionTime());
		for (String id : timestamp.getTimestampedCertificateIds()) {
			poeProvisioning.getValidationObject().add(getVOReference(id));
		}
		for (String id : timestamp.getTimestampedRevocationIds()) {
			poeProvisioning.getValidationObject().add(getVOReference(id));
		}
		for (String id : timestamp.getTimestampedTimestampIds()) {
			poeProvisioning.getValidationObject().add(getVOReference(id));
		}
		for (String id : timestamp.getTimestampedSignedDataIds()) {
			poeProvisioning.getValidationObject().add(getVOReference(id));
		}
		List<SignatureWrapper> timestampedSignatures = timestamp.getTimestampedSignatures();
		for (SignatureWrapper timestampedSignature : timestampedSignatures) {
			poeProvisioning.getSignatureReference().add(getSignatureReference(timestampedSignature));
		}
		return poeProvisioning;
	}
	
	private SignatureReferenceType getSignatureReference(SignatureWrapper timestampedSignature) {
		SignatureReferenceType signatureReference = objectFactory.createSignatureReferenceType();
		if (timestampedSignature != null) {
			signatureReference.setPAdESFieldName(timestampedSignature.getSignatureFieldName());
		}
		// TODO: get digest
//		signatureReference.setCanonicalizationMethod(value);
//		signatureReference.setDigestMethod();
//		signatureReference.setDigestValue(value);
		return signatureReference;
	}
	
	private void addSignerData(ValidationObjectListType validationObjectListType, XmlSignerData signedData, POEExtraction poeExtraction) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(signedData.getId());
		validationObject.setObjectType(ObjectType.SIGNED_DATA);
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		representation.setDigestAlgAndValue(getDigestAlgAndValueType(signedData.getDigestAlgoAndValue()));
		validationObject.setValidationObject(representation);
		validationObject.setPOE(getPOE(signedData.getId(), poeExtraction));
		validationObjectListType.getValidationObject().add(validationObject);
	}

	private void addRevocationData(ValidationObjectListType validationObjectListType, RevocationWrapper revocationData, POEExtraction poeExtraction) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(revocationData.getId());
		if (RevocationType.CRL.equals(revocationData.getRevocationType())) {
			validationObject.setObjectType(ObjectType.CRL);
		} else {
			validationObject.setObjectType(ObjectType.OCSP_RESPONSE);
		}
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		if (Utils.isArrayNotEmpty(revocationData.getBinaries())) {
			representation.setBase64(revocationData.getBinaries());
		} else {
			representation.setDigestAlgAndValue(getDigestAlgAndValueType(revocationData.getDigestAlgoAndValue()));
		}
//		Standard says choice
//		String sourceAddress = revocationData.getSourceAddress();
//		if (Utils.isStringNotEmpty(sourceAddress)) {
//			representation.setURI(sourceAddress);
//		}
		validationObject.setValidationObject(representation);
		validationObject.setPOE(getPOE(revocationData.getId(), poeExtraction));
		validationObject.setValidationReport(getValidationReport(revocationData));
		validationObjectListType.getValidationObject().add(validationObject);
	}

	private void addOrphanRevocation(ValidationObjectListType validationObjectListType, XmlOrphanRevocation orphanRevocation, POEExtraction poeExtraction) {
		ValidationObjectType validationObject = createOrphanToken(orphanRevocation.getToken(), poeExtraction);
		if (RevocationType.CRL.equals(orphanRevocation.getType())) {
			validationObject.setObjectType(ObjectType.CRL);
		} else {
			validationObject.setObjectType(ObjectType.OCSP_RESPONSE);
		}
		validationObjectListType.getValidationObject().add(validationObject);
	}
	
	private void addOrphanCertificate(ValidationObjectListType validationObjectListType, XmlOrphanToken orphanCertificate, POEExtraction poeExtraction) {
		ValidationObjectType orphanCertificateToken = createOrphanToken(orphanCertificate, poeExtraction);
		orphanCertificateToken.setObjectType(ObjectType.CERTIFICATE);
		validationObjectListType.getValidationObject().add(orphanCertificateToken);
	}
	
	private ValidationObjectType createOrphanToken(XmlOrphanToken orphanToken, POEExtraction poeExtraction) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(orphanToken.getId());
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		if (Utils.isArrayNotEmpty(orphanToken.getBase64Encoded())) {
			representation.setBase64(orphanToken.getBase64Encoded());
		} else {
			representation.setDigestAlgAndValue(getDigestAlgAndValueType(orphanToken.getDigestAlgoAndValue()));
		}
		validationObject.setValidationObject(representation);
		validationObject.setPOE(getPOE(orphanToken.getId(), poeExtraction));
		return validationObject;
	}

	private ValidationStatusType getSignatureValidationStatus(SignatureWrapper signature) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();

		Indication indication = detailedReport.getHighestIndication(signature.getId());
		if (indication != null) {
			fillIndication(validationStatus, indication);
			SubIndication subIndication = detailedReport.getHighestSubIndication(signature.getId());
			if (subIndication != null) {
				validationStatus.getSubIndication().add(eu.europa.esig.jaxb.validationreport.enums.SubIndication.valueOf(subIndication.name()));
			}
		}

		addValidationReportData(validationStatus, signature);
		return validationStatus;
	}

	private void fillIndication(ValidationStatusType validationStatus, Indication indication) {
		switch (indication) {
		case PASSED:
			validationStatus.setMainIndication(MainIndication.TOTAL_PASSED);
			break;
		case FAILED:
			validationStatus.setMainIndication(MainIndication.TOTAL_FAILED);
			break;
		case INDETERMINATE:
			validationStatus.setMainIndication(MainIndication.INDETERMINATE);
			break;
		default:
			throw new DSSException("Unsupported indication : " + indication);
		}
	}

	private ValidationStatusType getValidationStatus(AbstractTokenProxy token) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();
		fillIndicationSubIndication(validationStatus, detailedReport.getBasicBuildingBlocksIndication(token.getId()),
				detailedReport.getBasicBuildingBlocksSubIndication(token.getId()));
		addValidationReportData(validationStatus, token);
		return validationStatus;
	}

	private ValidationStatusType getValidationStatus(XmlConclusion conclusion) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();
		fillIndicationSubIndication(validationStatus, conclusion.getIndication(), conclusion.getSubIndication());
		return validationStatus;
	}

	private void fillIndicationSubIndication(ValidationStatusType validationStatus, Indication indication, SubIndication subIndication) {
		if (indication != null) {
			validationStatus.setMainIndication(MainIndication.valueOf(indication.name()));
		}
		if (subIndication != null) {
			validationStatus.getSubIndication().add(eu.europa.esig.jaxb.validationreport.enums.SubIndication.valueOf(subIndication.name()));
		}
	}

	private void addValidationReportData(ValidationStatusType validationStatus, AbstractTokenProxy token) {
		XmlBasicBuildingBlocks basicBuildingBlock = detailedReport.getBasicBuildingBlockById(token.getId());
		XmlSubXCV signingCertificate = detailedReport.getSigningCertificate(token.getId());

		if (basicBuildingBlock != null || signingCertificate != null) {
			ValidationReportDataType validationReportData = objectFactory.createValidationReportDataType();
			if (basicBuildingBlock != null) {
				XmlCertificateChain certificateChain = basicBuildingBlock.getCertificateChain();
				if (certificateChain != null) {
					fillCertificateChainAndTrustAnchor(validationReportData, certificateChain);
				}

				XmlSAV sav = basicBuildingBlock.getSAV();
				if (sav != null && sav.getCryptographicInfo() != null) {
					fillCryptographicInfo(validationReportData, token.getId(), sav.getCryptographicInfo());
				}
			}

			if (signingCertificate != null && signingCertificate.getRevocationInfo() != null) {
				fillRevocationInfo(validationReportData, signingCertificate.getRevocationInfo());
			}

			validationStatus.getAssociatedValidationReportData().add(validationReportData);
		}
	}

	private void fillCryptographicInfo(ValidationReportDataType validationReportData, String tokenId, XmlCryptographicInformation cryptographicInfo) {
		CryptoInformationType cryptoInformationType = objectFactory.createCryptoInformationType();
		cryptoInformationType.setValidationObjectId(getVOReference(tokenId));
		cryptoInformationType.setAlgorithm(cryptographicInfo.getAlgorithm());
		cryptoInformationType.setSecureAlgorithm(cryptographicInfo.isSecure());
		cryptoInformationType.setNotAfter(cryptographicInfo.getNotAfter());
		validationReportData.setCryptoInformation(cryptoInformationType);
	}

	private void fillRevocationInfo(ValidationReportDataType validationReportData, XmlRevocationInformation revocationInfo) {
		RevocationStatusInformationType revocationStatusInformationType = objectFactory.createRevocationStatusInformationType();
		revocationStatusInformationType.setRevocationTime(revocationInfo.getRevocationDate());
		revocationStatusInformationType.setRevocationObject(getVOReference(revocationInfo.getRevocationId()));
		revocationStatusInformationType.setValidationObjectId(getVOReference(revocationInfo.getCertificateId()));
		if (revocationInfo.getReason() != null) {
			revocationStatusInformationType.setRevocationReason(RevocationReason.valueOf(revocationInfo.getReason().name()));
		}
		validationReportData.setRevocationStatusInformation(revocationStatusInformationType);
	}

	private void fillCertificateChainAndTrustAnchor(ValidationReportDataType validationReportData, XmlCertificateChain certificateChain) {
		CertificateChainType certificateChainType = objectFactory.createCertificateChainType();
		VOReferenceType signingCert = null;
		VOReferenceType trustAnchor = null;

		List<XmlChainItem> chainItem = certificateChain.getChainItem();
		for (int i = 0; i < chainItem.size(); i++) {
			XmlChainItem currentChainItem = chainItem.get(i);
			VOReferenceType currentVORef = getVOReference(currentChainItem.getId());
			XmlCertificateSourceType source = currentChainItem.getSource();

			boolean isSigningCert = (i == 0);
			boolean isTrustAnchor = isTrustAnchor(source);

			if (isSigningCert || isTrustAnchor) {
				if (isSigningCert) {
					signingCert = currentVORef;
				}
				if (isTrustAnchor) {
					trustAnchor = currentVORef;
				}
			} else {
				certificateChainType.getIntermediateCertificate().add(currentVORef);
			}
		}

		certificateChainType.setSigningCertificate(signingCert);
		certificateChainType.setTrustAnchor(trustAnchor);

		validationReportData.setCertificateChain(certificateChainType);
		validationReportData.setTrustAnchor(trustAnchor);
	}

	private boolean isTrustAnchor(XmlCertificateSourceType source) {
		return XmlCertificateSourceType.TRUSTED_LIST.equals(source) || XmlCertificateSourceType.TRUSTED_STORE.equals(source);
	}

	private SignatureIdentifierType getSignatureIdentifier(SignatureWrapper sigWrapper) {
		SignatureIdentifierType sigId = objectFactory.createSignatureIdentifierType();
		sigId.setId(sigWrapper.getId());
		sigId.setDAIdentifier(sigWrapper.getDAIdentifier());
		sigId.setDocHashOnly(sigWrapper.isDocHashOnly());
		sigId.setHashOnly(sigWrapper.isHashOnly());
		sigId.setDigestAlgAndValue(getDTBSRDigestAlgAndValue(sigWrapper.getDigestMatchers()));
		SignatureValueType sigValue = new SignatureValueType();
		sigValue.setValue(sigWrapper.getSignatureValue());
		sigId.setSignatureValue(sigValue);
		return sigId;
	}
	
	private DigestAlgAndValueType getDTBSRDigestAlgAndValue(List<XmlDigestMatcher> digestMatchers) {
		XmlDigestMatcher digestMatcher = null;
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
				if ( (digestMatcher == null || DigestMatcherType.SIGNED_PROPERTIES.equals(xmlDigestMatcher.getType()) || 
						DigestMatcherType.CONTENT_DIGEST.equals(xmlDigestMatcher.getType()) ) &&
						Utils.isStringNotEmpty(xmlDigestMatcher.getDigestMethod()) && Utils.isArrayNotEmpty(xmlDigestMatcher.getDigestValue())) {
					digestMatcher = xmlDigestMatcher;
				}
			}
		}
		return digestMatcher == null ? null : getDigestAlgAndValueType(digestMatcher.getDigestMethod(), digestMatcher.getDigestValue());
	}
	
	private void getSignersDocuments(SignatureValidationReportType signatureValidationReport, SignatureWrapper sigWrapper) {
		List<XmlSignatureScope> signerData = sigWrapper.getSignatureScopes();
		for (XmlSignatureScope xmlSignatureScope : signerData) {
			SignersDocumentType signersDocumentType = objectFactory.createSignersDocumentType();
			signersDocumentType.setDigestAlgAndValue(getDigestAlgAndValueType(xmlSignatureScope.getSignerData().getDigestAlgoAndValue()));
			signersDocumentType.setSignersDocumentRef(getVOReference(xmlSignatureScope.getSignerData().getId()));
			signatureValidationReport.getSignersDocument().add(signersDocumentType);
		}
	}

	private SignatureAttributesType getSignatureAttributes(SignatureWrapper sigWrapper) {
		SignatureAttributesType sigAttributes = objectFactory.createSignatureAttributesType();
		// &lt;element name="SigningTime" type="{http://uri.etsi.org/19102/v1.2.1#}SASigningTimeType"/&gt;
		addSigningTime(sigAttributes, sigWrapper);
		// &lt;element name="SigningCertificate" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		addSigningCertificate(sigAttributes, sigWrapper);
		// &lt;element name="DataObjectFormat" type="{http://uri.etsi.org/19102/v1.2.1#}SADataObjectFormatType"/&gt;
		addDataObjectFormat(sigAttributes, sigWrapper);
		// &lt;element name="CommitmentTypeIndication" type="{http://uri.etsi.org/19102/v1.2.1#}SACommitmentTypeIndicationType"/&gt;
		addCommitmentTypeIndications(sigAttributes, sigWrapper);
		// &lt;element name="AllDataObjectsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
		// see TS 119 102-2 - V1.2.1 A.6.3 CAdES
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.CONTENT_TIMESTAMP);
		// &lt;element name="IndividualDataObjectsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		// &lt;element name="SigPolicyIdentifier" type="{http://uri.etsi.org/19102/v1.2.1#}SASigPolicyIdentifierType"/&gt;
		addSigPolicyIdentifier(sigAttributes, sigWrapper);
		// &lt;element name="SignatureProductionPlace" type="{http://uri.etsi.org/19102/v1.2.1#}SASignatureProductionPlaceType"/&gt;
		addProductionPlace(sigAttributes, sigWrapper);
		// &lt;element name="SignerRole" type="{http://uri.etsi.org/19102/v1.2.1#}SASignerRoleType"/&gt;
		addSignerRoles(sigAttributes, sigWrapper);
		// &lt;element name="CounterSignature" type="{http://uri.etsi.org/19102/v1.2.1#}SACounterSignatureType"/&gt;
		addCounterSignatures(sigAttributes, sigWrapper);
		// &lt;element name="SignatureTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.SIGNATURE_TIMESTAMP);
		// &lt;element name="CompleteCertificateRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		addCompleteCertificateRefs(sigAttributes, sigWrapper);
		// &lt;element name="CompleteRevocationRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SARevIDListType"/&gt;
		addCompleteRevocationRefs(sigAttributes, sigWrapper);
		// &lt;element name="AttributeCertificateRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		addAttributeCertificateRefs(sigAttributes, sigWrapper);
		// &lt;element name="AttributeRevocationRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SARevIDListType"/&gt;
		addAttributeRevocationRefs(sigAttributes, sigWrapper);
		// &lt;element name="SigAndRefsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.VALIDATION_DATA_TIMESTAMP);
		// &lt;element name="RefsOnlyTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		// &lt;element name="CertificateValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addCertificateValues(sigAttributes, sigWrapper);
		// &lt;element name="RevocationValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addRevocationValues(sigAttributes, sigWrapper);
		// &lt;element name="AttrAuthoritiesCertValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addAttrAuthoritiesCertValues(sigAttributes, sigWrapper);
		// &lt;element name="AttributeRevocationValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addAttributeRevocationValues(sigAttributes, sigWrapper);
		// &lt;element name="TimeStampValidationData" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addTimeStampValidationData(sigAttributes, sigWrapper);
		// &lt;element name="ArchiveTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.ARCHIVE_TIMESTAMP);
		// &lt;element name="RenewedDigests" type="{http://uri.etsi.org/19102/v1.2.1#}SAListOfIntegersType"/&gt;
		// &lt;element name="MessageDigest" type="{http://uri.etsi.org/19102/v1.2.1#}SAMessageDigestType"/&gt;
		addMessageDigest(sigAttributes, sigWrapper);
		// &lt;element name="DSS" type="{http://uri.etsi.org/19102/v1.2.1#}SADSSType"/&gt;
		addDSS(sigAttributes, sigWrapper);
		// &lt;element name="VRI" type="{http://uri.etsi.org/19102/v1.2.1#}SAVRIType"/&gt;
		addVRI(sigAttributes, sigWrapper);
		// &lt;element name="DocTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByLocation(sigAttributes, sigWrapper, TimestampLocation.DOC_TIMESTAMP);
		// &lt;element name="Reason" type="{http://uri.etsi.org/19102/v1.2.1#}SAReasonType"/&gt;
		addReason(sigAttributes, sigWrapper);
		// &lt;element name="Name" type="{http://uri.etsi.org/19102/v1.2.1#}SANameType"/&gt;
		addSignerName(sigAttributes, sigWrapper);
		// &lt;element name="ContactInfo" type="{http://uri.etsi.org/19102/v1.2.1#}SAContactInfoType"/&gt;
		addContactInfo(sigAttributes, sigWrapper);
		// &lt;element name="SubFilter" type="{http://uri.etsi.org/19102/v1.2.1#}SASubFilterType"/&gt;
		addSubFilter(sigAttributes, sigWrapper);
		// &lt;element name="ByteRange" type="{http://uri.etsi.org/19102/v1.2.1#}SAListOfIntegersType"/&gt;
		addSignatureByteRange(sigAttributes, sigWrapper);
		// &lt;element name="Filter" type="{http://uri.etsi.org/19102/v1.2.1#}SAFilterType"/&gt;
		addFilter(sigAttributes, sigWrapper);
		return sigAttributes;
	}

	private void addAttrAuthoritiesCertValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> certIds = sigWrapper.getFoundCertificateIds(CertificateOriginType.ATTR_AUTORITIES_CERT_VALUES);
		if (Utils.isCollectionNotEmpty(certIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttrAuthoritiesCertValues(buildTokenList(certIds)));
		}
	}

	private void addTimeStampValidationData(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> refIds = sigWrapper.getFoundCertificateIds(CertificateOriginType.TIMESTAMP_DATA_VALIDATION);
		refIds.addAll(sigWrapper.getRevocationIdsByOrigin(XmlRevocationOrigin.TIMESTAMP_VALIDATION_DATA));
		if (Utils.isCollectionNotEmpty(refIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeTimeStampValidationData(buildTokenList(refIds)));
		}
	}

	private void addCertificateValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> certIds = sigWrapper.getFoundCertificateIds(CertificateOriginType.CERTIFICATE_VALUES);
		if (Utils.isCollectionNotEmpty(certIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCertificateValues(buildTokenList(certIds)));
		}
	}

	private void addAttributeCertificateRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByRefOrigin(CertificateRefOriginType.ATTRIBUTE_CERTIFICATE_REFS);
		if (Utils.isCollectionNotEmpty(certs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttributeCertificateRefs(buildCertIDListType(certs)));
		}
	}

	private void addCompleteCertificateRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByRefOrigin(CertificateRefOriginType.COMPLETE_CERTIFICATE_REFS);
		if (Utils.isCollectionNotEmpty(certs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCompleteCertificateRefs(buildCertIDListType(certs)));
		}
	}

	private void addSigningCertificate(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByRefOrigin(CertificateRefOriginType.SIGNING_CERTIFICATE);
		if (Utils.isCollectionNotEmpty(certs)) {
			JAXBElement<SACertIDListType> signingCertAttribute = objectFactory.createSignatureAttributesTypeSigningCertificate(buildCertIDListType(certs));
			if (sigWrapper.isBLevelTechnicallyValid()) {
				signingCertAttribute.getValue().setSigned(true);
			}
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(signingCertAttribute);
		}
	}

	private AttributeBaseType buildTokenList(List<String> ids) {
		AttributeBaseType attributeBaseType = objectFactory.createAttributeBaseType();
		for (String id : ids) {
			attributeBaseType.getAttributeObject().add(getVOReference(id));
		}
		return attributeBaseType;
	}

	private SACertIDListType buildCertIDListType(List<XmlFoundCertificate> certs) {
		SACertIDListType certIdList = objectFactory.createSACertIDListType();
		for (XmlFoundCertificate cert : certs) {
			String id;
			if (cert instanceof XmlRelatedCertificate) {
				id = ((XmlRelatedCertificate)cert).getCertificate().getId();
			} else {
				id = ((XmlOrphanCertificate)cert).getToken().getId();
			}
			certIdList.getAttributeObject().add(getVOReference(id));
			List<XmlCertificateRef> certificateRefs = cert.getCertificateRefs();
			for (XmlCertificateRef certificateRef : certificateRefs) {
				if (certificateRef != null && certificateRef.getDigestAlgoAndValue() != null) {
					SACertIDType certIDType = objectFactory.createSACertIDType();
					XmlDigestAlgoAndValue digestAlgoAndValue = certificateRef.getDigestAlgoAndValue();
					DigestMethodType digestMethodType = new DigestMethodType();
					digestMethodType.setAlgorithm(DigestAlgorithm.forName(digestAlgoAndValue.getDigestMethod()).getXmlId());
					certIDType.setDigestMethod(digestMethodType);
					certIDType.setDigestValue(digestAlgoAndValue.getDigestValue());
					if (certificateRef.getIssuerSerial() != null) {
						certIDType.setX509IssuerSerial(certificateRef.getIssuerSerial());
					}
					certIdList.getCertID().add(certIDType);
				}
			} 
		}
		return certIdList;
	}
	
	private void addCompleteRevocationRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlRevocationRef> revocationRefs = sigWrapper.getFoundRevocationRefsByOrigin(XmlRevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
				.add(objectFactory.createSignatureAttributesTypeCompleteRevocationRefs(buildRevIDListType(revocationRefs)));
		}
	}
	
	private void addAttributeRevocationRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlRevocationRef> revocationRefs = sigWrapper.getFoundRevocationRefsByOrigin(XmlRevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
				.add(objectFactory.createSignatureAttributesTypeAttributeRevocationRefs(buildRevIDListType(revocationRefs)));
		}
	}
	
	private SARevIDListType buildRevIDListType(List<XmlRevocationRef> revocationRefs) {
		SARevIDListType revIDListType = objectFactory.createSARevIDListType();
		
		for (XmlRevocationRef xmlRevocationRef : revocationRefs) {
			// ProducedAt parameter is only for OCSP refs
			if (xmlRevocationRef.getProducedAt() == null) {
				SACRLIDType sacrlidType = objectFactory.createSACRLIDType();
				DigestMethodType digestMethodType = new DigestMethodType();
				XmlDigestAlgoAndValue digestAlgoAndValue = xmlRevocationRef.getDigestAlgoAndValue();
				digestMethodType.setAlgorithm(DigestAlgorithm.forName(digestAlgoAndValue.getDigestMethod()).getXmlId());
				sacrlidType.setDigestMethod(digestMethodType);
				sacrlidType.setDigestValue(digestAlgoAndValue.getDigestValue());
				revIDListType.getCRLIDOrOCSPID().add(sacrlidType);
			} else {
				SAOCSPIDType saocspidType = objectFactory.createSAOCSPIDType();
				saocspidType.setProducedAt(xmlRevocationRef.getProducedAt());
				if (Utils.isStringNotEmpty(xmlRevocationRef.getResponderIdName())) {
					saocspidType.setResponderIDByName(xmlRevocationRef.getResponderIdName());
				} else {
					saocspidType.setResponderIDByKey(xmlRevocationRef.getResponderIdKey());
				}
				revIDListType.getCRLIDOrOCSPID().add(saocspidType);
			}
		}
		
		return revIDListType;
	}
	
	private void addRevocationValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> revocationRefs = sigWrapper.getRevocationIdsByOrigin(XmlRevocationOrigin.REVOCATION_VALUES);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeRevocationValues(buildTokenList(revocationRefs)));
		}
	}
	
	private void addAttributeRevocationValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> revocationRefs = sigWrapper.getRevocationIdsByOrigin(XmlRevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttributeRevocationValues(buildTokenList(revocationRefs)));
		}
	}

	private void addMessageDigest(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		XmlDigestMatcher messageDigest = sigWrapper.getMessageDigest();
		if (messageDigest != null) {
			SAMessageDigestType messageDigestType = objectFactory.createSAMessageDigestType();
			messageDigestType.setDigest(messageDigest.getDigestValue());
			setSignedIfValid(sigWrapper, messageDigestType);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeMessageDigest(messageDigestType));
		}
	}

	private void addTimestampsByType(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper, TimestampType timestampType) {
		List<TimestampWrapper> timestampListByType = sigWrapper.getTimestampListByType(timestampType);
		// remove document timestamps (they will be present in DocTimeStamp element)
		List<TimestampWrapper> docTimestamps = sigWrapper.getTimestampListByLocation(TimestampLocation.DOC_TIMESTAMP);
		timestampListByType.removeAll(docTimestamps);

		boolean isSigned = sigWrapper.isBLevelTechnicallyValid() && isSignedAttribute(timestampType);

		for (TimestampWrapper timestampWrapper : timestampListByType) {
			SATimestampType timestamp = getSATimestampType(timestampWrapper);
			JAXBElement<SATimestampType> wrap = wrap(timestampType, timestamp);
			if (isSigned) {
				wrap.getValue().setSigned(isSigned);
			}
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(wrap);
		}
	}

	private boolean isSignedAttribute(TimestampType timestampType) {
		return TimestampType.CONTENT_TIMESTAMP.equals(timestampType) || TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.equals(timestampType)
				|| TimestampType.ALL_DATA_OBJECTS_TIMESTAMP.equals(timestampType);
	}

	private void addTimestampsByLocation(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper, TimestampLocation timestampLocation) {
		List<TimestampWrapper> timestampListByType = sigWrapper.getTimestampListByLocation(timestampLocation);
		for (TimestampWrapper timestampWrapper : timestampListByType) {
			SATimestampType timestamp = getSATimestampType(timestampWrapper);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(wrap(timestampLocation, timestamp));
		}
	}
	
	private SATimestampType getSATimestampType(TimestampWrapper timestampWrapper) {
		SATimestampType timestamp = objectFactory.createSATimestampType();
		timestamp.setTimeStampValue(timestampWrapper.getProductionTime());
		timestamp.getAttributeObject().add(getVOReference(timestampWrapper.getId()));
		return timestamp;
	}

	private JAXBElement<SATimestampType> wrap(TimestampType timestampType, SATimestampType timestamp) {
		switch (timestampType) {
			case SIGNATURE_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeSignatureTimeStamp(timestamp);
			case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeIndividualDataObjectsTimeStamp(timestamp);
			case ALL_DATA_OBJECTS_TIMESTAMP:
			case CONTENT_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeAllDataObjectsTimeStamp(timestamp);
			case VALIDATION_DATA_REFSONLY_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeRefsOnlyTimeStamp(timestamp);
			case VALIDATION_DATA_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeSigAndRefsTimeStamp(timestamp);
			case ARCHIVE_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeArchiveTimeStamp(timestamp);
			default:
				throw new DSSException("Unsupported timestamp type " + timestampType);
		}
	}

	private JAXBElement<SATimestampType> wrap(TimestampLocation timestampLocation, SATimestampType timestamp) {
		switch (timestampLocation) {
			case DOC_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeDocTimeStamp(timestamp);
			default:
				throw new DSSException("Unsupported timestamp type " + timestampLocation);
		}
	}
	
	private void addSigPolicyIdentifier(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String policyId = sigWrapper.getPolicyId();
		if (Utils.isStringNotEmpty(policyId) && // exclude empty and default values
				!SignaturePolicy.IMPLICIT_POLICY.equals(policyId)) {
			SASigPolicyIdentifierType saSigPolicyIdentifierType = objectFactory.createSASigPolicyIdentifierType();
			saSigPolicyIdentifierType.setSigPolicyId(policyId);
			setSignedIfValid(sigWrapper, saSigPolicyIdentifierType);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
				.add(objectFactory.createSignatureAttributesTypeSigPolicyIdentifier(saSigPolicyIdentifierType));
		}
	}

	private void addDataObjectFormat(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String contentType = sigWrapper.getContentType();
		String mimeType = sigWrapper.getMimeType();
		if (Utils.isStringNotEmpty(contentType) || Utils.isStringNotEmpty(mimeType)) {
			SADataObjectFormatType dataObjectFormatType = objectFactory.createSADataObjectFormatType();
			if (Utils.isStringNotEmpty(contentType)) {
				dataObjectFormatType.setContentType(contentType);
			}
			if (Utils.isStringNotEmpty(mimeType)) {
				dataObjectFormatType.setMimeType(mimeType);
			}
			setSignedIfValid(sigWrapper, dataObjectFormatType);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeDataObjectFormat(dataObjectFormatType));
		}
	}

	private void addCommitmentTypeIndications(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> commitmentTypeIdentifiers = sigWrapper.getCommitmentTypeIdentifiers();
		if (Utils.isCollectionNotEmpty(commitmentTypeIdentifiers)) {
			for (String commitmentTypeIdentifier : commitmentTypeIdentifiers) {
				SACommitmentTypeIndicationType commitmentType = objectFactory.createSACommitmentTypeIndicationType();
				commitmentType.setCommitmentTypeIdentifier(commitmentTypeIdentifier);
				setSignedIfValid(sigWrapper, commitmentType);
				sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
						.add(objectFactory.createSignatureAttributesTypeCommitmentTypeIndication(commitmentType));
			}
		}
	}

	private void addSignerRoles(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> claimedRoles = sigWrapper.getClaimedRoles();
		List<String> certifiedRoles = sigWrapper.getCertifiedRoles();
		if (Utils.isCollectionNotEmpty(claimedRoles) || Utils.isCollectionNotEmpty(certifiedRoles)) {
			SASignerRoleType signerRoleType = objectFactory.createSASignerRoleType();
			addSignerRoles(signerRoleType, claimedRoles, EndorsementType.CLAIMED);
			addSignerRoles(signerRoleType, certifiedRoles, EndorsementType.CERTIFIED);
			setSignedIfValid(sigWrapper, signerRoleType);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeSignerRole(signerRoleType));
		}
	}

	private void addSignerRoles(SASignerRoleType signerRoleType, List<String> roles, EndorsementType endorsement) {
		for (String role : roles) {
			SAOneSignerRoleType oneSignerRole = objectFactory.createSAOneSignerRoleType();
			oneSignerRole.setRole(role);
			oneSignerRole.setEndorsementType(endorsement);
			signerRoleType.getRoleDetails().add(oneSignerRole);
		}
	}
	
	private void addCounterSignatures(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignaturesForMasterSignature(sigWrapper);
		for (SignatureWrapper counterSignature : counterSignatures) {
			SACounterSignatureType saCounterSignatureType = objectFactory.createSACounterSignatureType();
			saCounterSignatureType.getAttributeObject().add(getVOReference(counterSignature.getId()));
			SignatureReferenceType signatureReference = getSignatureReference(counterSignature);
			saCounterSignatureType.setCounterSignature(signatureReference);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(
					objectFactory.createSignatureAttributesTypeCounterSignature(saCounterSignatureType));
		}
	}

	private void addProductionPlace(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		if (sigWrapper.isSignatureProductionPlacePresent()) {
			final String address = sigWrapper.getAddress();
			final String city = sigWrapper.getCity();
			final String stateOrProvince = sigWrapper.getStateOrProvince();
			final String postalCode = sigWrapper.getPostalCode();
			final String countryName = sigWrapper.getCountryName();

			if (Utils.isAtLeastOneNotEmpty(address, city, stateOrProvince, postalCode, countryName)) {
				SASignatureProductionPlaceType sigProductionPlace = objectFactory.createSASignatureProductionPlaceType();
				if (Utils.isStringNotEmpty(address)) {
					sigProductionPlace.getAddressString().add(address);
				}
				if (Utils.isStringNotEmpty(city)) {
					sigProductionPlace.getAddressString().add(city);
				}
				if (Utils.isStringNotEmpty(stateOrProvince)) {
					sigProductionPlace.getAddressString().add(stateOrProvince);
				}
				if (Utils.isStringNotEmpty(postalCode)) {
					sigProductionPlace.getAddressString().add(postalCode);
				}
				if (Utils.isStringNotEmpty(countryName)) {
					sigProductionPlace.getAddressString().add(countryName);
				}
				setSignedIfValid(sigWrapper, sigProductionPlace);
				sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
						.add(objectFactory.createSignatureAttributesTypeSignatureProductionPlace(sigProductionPlace));
			}
		}
	}

	private void addFilter(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String filter = sigWrapper.getFilter();
		if (Utils.isStringNotEmpty(filter)) {
			SAFilterType filterType = objectFactory.createSAFilterType();
			filterType.setFilter(filter);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeFilter(filterType));
		}
	}

	private void addSubFilter(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String subFilter = sigWrapper.getSubFilter();
		if (Utils.isStringNotEmpty(subFilter)) {
			SASubFilterType subFilterType = objectFactory.createSASubFilterType();
			subFilterType.setSubFilterElement(subFilter);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeSubFilter(subFilterType));
		}
	}

	private void addContactInfo(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String contactInfo = sigWrapper.getContactInfo();
		if (Utils.isStringNotEmpty(contactInfo)) {
			SAContactInfoType contactInfoType = objectFactory.createSAContactInfoType();
			contactInfoType.setContactInfoElement(contactInfo);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeContactInfo(contactInfoType));
		}
	}

	private void addSignerName(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String signerName = sigWrapper.getSignerName();
		if (Utils.isStringNotEmpty(signerName)) {
			SANameType nameType = objectFactory.createSANameType();
			nameType.setNameElement(signerName);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeName(nameType));
		}
	}

	private void addReason(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String reason = sigWrapper.getReason();
		if (Utils.isStringNotEmpty(reason)) {
			SAReasonType reasonType = objectFactory.createSAReasonType();
			reasonType.setReasonElement(reason);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeReason(reasonType));
		}
	}
	
	private void addSignatureByteRange(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<BigInteger> signatureByteRange = sigWrapper.getSignatureByteRange();
		if (Utils.isCollectionNotEmpty(signatureByteRange)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeByteRange(signatureByteRange));
		}
	}

	private void addDSS(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> certIds = sigWrapper.getFoundCertificateIds(CertificateOriginType.DSS);
		List<String> crlIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, XmlRevocationOrigin.DSS_DICTIONARY);
		List<String> ocspIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.DSS_DICTIONARY);
		if (Utils.isCollectionNotEmpty(certIds) || Utils.isCollectionNotEmpty(crlIds) || Utils.isCollectionNotEmpty(ocspIds)) {
			SADSSType dssType = objectFactory.createSADSSType();
			if (Utils.isCollectionNotEmpty(certIds)) {
				dssType.setCerts(getVOReference(certIds));
			}
			if (Utils.isCollectionNotEmpty(crlIds)) {
				dssType.setCRLs(getVOReference(crlIds));
			}
			if (Utils.isCollectionNotEmpty(ocspIds)) {
				dssType.setOCSPs(getVOReference(ocspIds));
			}
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeDSS(dssType));
		}
	}

	private void addVRI(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> certIds = sigWrapper.getFoundCertificateIds(CertificateOriginType.VRI);
		List<String> crlIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, XmlRevocationOrigin.VRI_DICTIONARY);
		List<String> ocspIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.VRI_DICTIONARY);

		if (Utils.isCollectionNotEmpty(certIds) || Utils.isCollectionNotEmpty(crlIds) || Utils.isCollectionNotEmpty(ocspIds)) {
			SAVRIType vriType = objectFactory.createSAVRIType();
			if (Utils.isCollectionNotEmpty(certIds)) {
				vriType.setCerts(getVOReference(certIds));
			}
			if (Utils.isCollectionNotEmpty(crlIds)) {
				vriType.setCRLs(getVOReference(crlIds));
			}
			if (Utils.isCollectionNotEmpty(ocspIds)) {
				vriType.setOCSPs(getVOReference(ocspIds));
			}
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeVRI(vriType));
		}
	}

	private void addSigningTime(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		Date dateTime = sigWrapper.getDateTime();
		if (dateTime != null) {
			SASigningTimeType saSigningTimeType = objectFactory.createSASigningTimeType();
			saSigningTimeType.setTime(dateTime);
			setSignedIfValid(sigWrapper, saSigningTimeType);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeSigningTime(saSigningTimeType));
		}
	}

	private void setSignedIfValid(SignatureWrapper sigWrapper, AttributeBaseType attribute) {
		if (sigWrapper.isBLevelTechnicallyValid()) {
			attribute.setSigned(true);
		}
	}

}
