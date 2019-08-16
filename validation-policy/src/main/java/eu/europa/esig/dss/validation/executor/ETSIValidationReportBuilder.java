package eu.europa.esig.dss.validation.executor;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.xml.bind.JAXBElement;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.detailedreport.jaxb.XmlChainItem;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicInformation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationInformation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignaturePolicyType;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.BasicBuildingBlockDefinition;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.validationreport.enums.ConstraintStatus;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.SignatureValidationProcessID;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.AttributeBaseType;
import eu.europa.esig.validationreport.jaxb.CertificateChainType;
import eu.europa.esig.validationreport.jaxb.ConstraintStatusType;
import eu.europa.esig.validationreport.jaxb.CryptoInformationType;
import eu.europa.esig.validationreport.jaxb.IndividualValidationConstraintReportType;
import eu.europa.esig.validationreport.jaxb.ObjectFactory;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.RevocationStatusInformationType;
import eu.europa.esig.validationreport.jaxb.SACRLIDType;
import eu.europa.esig.validationreport.jaxb.SACertIDListType;
import eu.europa.esig.validationreport.jaxb.SACertIDType;
import eu.europa.esig.validationreport.jaxb.SACommitmentTypeIndicationType;
import eu.europa.esig.validationreport.jaxb.SAContactInfoType;
import eu.europa.esig.validationreport.jaxb.SACounterSignatureType;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SADataObjectFormatType;
import eu.europa.esig.validationreport.jaxb.SAFilterType;
import eu.europa.esig.validationreport.jaxb.SAMessageDigestType;
import eu.europa.esig.validationreport.jaxb.SANameType;
import eu.europa.esig.validationreport.jaxb.SAOCSPIDType;
import eu.europa.esig.validationreport.jaxb.SAOneSignerRoleType;
import eu.europa.esig.validationreport.jaxb.SAReasonType;
import eu.europa.esig.validationreport.jaxb.SARevIDListType;
import eu.europa.esig.validationreport.jaxb.SASigPolicyIdentifierType;
import eu.europa.esig.validationreport.jaxb.SASignatureProductionPlaceType;
import eu.europa.esig.validationreport.jaxb.SASignerRoleType;
import eu.europa.esig.validationreport.jaxb.SASigningTimeType;
import eu.europa.esig.validationreport.jaxb.SASubFilterType;
import eu.europa.esig.validationreport.jaxb.SATimestampType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureQualityType;
import eu.europa.esig.validationreport.jaxb.SignatureReferenceType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationProcessType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationConstraintsEvaluationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectRepresentationType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportDataType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import eu.europa.esig.validationreport.jaxb.ValidationTimeInfoType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;
import eu.europa.esig.xmldsig.jaxb.DigestMethodType;
import eu.europa.esig.xmldsig.jaxb.SignatureValueType;

public class ETSIValidationReportBuilder {

	private final ObjectFactory objectFactory = new ObjectFactory();
	private final Date currentTime;
	private final DiagnosticData diagnosticData;
	private final DetailedReport detailedReport;

	public ETSIValidationReportBuilder(Date currentTime, DiagnosticData diagnosticData, DetailedReport detailedReport) {
		this.currentTime = currentTime;
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
	}

	public ValidationReportType build() {
		ValidationReportType result = objectFactory.createValidationReportType();

		if (!diagnosticData.getSignatures().isEmpty()) {
			// iterate over the complete list of signatures, including counter signatures
			for (SignatureWrapper sigWrapper : diagnosticData.getSignatures()) {
				result.getSignatureValidationReport().add(getSignatureValidationReport(sigWrapper));
			}
		} else {
			result.getSignatureValidationReport().add(noSignatureFoundReport());
		}

		ValidationObjectListType signatureValidationObjects = getSignatureValidationObjects();
		if (!signatureValidationObjects.getValidationObject().isEmpty()) {
			result.setSignatureValidationObjects(signatureValidationObjects);
		}

		return result;
	}

	private SignatureValidationReportType getSignatureValidationReport(SignatureWrapper sigWrapper) {
		SignatureValidationReportType signatureValidationReport = objectFactory.createSignatureValidationReportType();
		signatureValidationReport.setSignatureIdentifier(getSignatureIdentifier(sigWrapper));
		getSignersDocuments(signatureValidationReport, sigWrapper);
		SignatureAttributesType signatureAttributes = getSignatureAttributes(sigWrapper);
		if (!signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().isEmpty()) {
			signatureValidationReport.setSignatureAttributes(signatureAttributes);
		}
		signatureValidationReport.setSignerInformation(getSignerInformation(sigWrapper));
		signatureValidationReport.setSignatureQuality(getSignatureQuality(sigWrapper));
		signatureValidationReport.setSignatureValidationProcess(getSignatureValidationProcess(sigWrapper));
		signatureValidationReport.setSignatureValidationStatus(getSignatureValidationStatus(sigWrapper));
		signatureValidationReport.setValidationTimeInfo(getValidationTimeInfo(sigWrapper));
		signatureValidationReport.setValidationConstraintsEvaluationReport(getValidationConstraintsEvaluationReport(sigWrapper));
		return signatureValidationReport;
	}

	private SignatureValidationReportType noSignatureFoundReport() {
		SignatureValidationReportType signatureValidationReport = objectFactory.createSignatureValidationReportType();
		signatureValidationReport.setSignatureValidationStatus(noSignatureFoundValidationStatus());
		return signatureValidationReport;
	}

	private ValidationStatusType noSignatureFoundValidationStatus() {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();
		validationStatus.setMainIndication(Indication.NO_SIGNATURE_FOUND);
		return validationStatus;
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
		XmlStatus pseudoUseStatus = getPseudoUseStatus(token);
		if (pseudoUseStatus != null) {
			signerInfo.setPseudonym(isPseudoUse(pseudoUseStatus));
		}
		signerInfo.setSigner(signingCert.getReadableCertificateName());
		signerInfo.setSignerCertificate(getVOReference(signingCert.getId()));
		return signerInfo;
	}
	
	private XmlStatus getPseudoUseStatus(AbstractTokenProxy token) {
		XmlSubXCV signingCertificateXCV = detailedReport.getSigningCertificate(token.getId());
		if (signingCertificateXCV != null) {
			List<XmlConstraint> constraints = signingCertificateXCV.getConstraint();
			for (XmlConstraint xmlConstraint : constraints) {
				if (MessageTag.BBB_XCV_PSEUDO_USE.name().equals(xmlConstraint.getName().getNameId())) {
					XmlStatus status = xmlConstraint.getStatus();
					return status;
				}
			}
		}
		return null;
	}

	private Boolean isPseudoUse(XmlStatus status) {
		return (XmlStatus.OK != status) && (XmlStatus.IGNORED != status);
	}
	
	private SignatureQualityType getSignatureQuality(SignatureWrapper signatureWrapper) {
		SignatureQualification signatureQualification = detailedReport.getSignatureQualification(signatureWrapper.getId());
		if (signatureQualification != null) {
			SignatureQualityType signatureQualityType = objectFactory.createSignatureQualityType();
			signatureQualityType.getSignatureQualityInformation().add(signatureQualification.getUri());
			return signatureQualityType;
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
		validationObject.setValidationObjectRepresentation(representation);
		validationObject.setPOE(getPOE(certificate.getId(), poeExtraction));
		validationObjectListType.getValidationObject().add(validationObject);
	}
	
	private DigestAlgAndValueType getDigestAlgAndValueType(XmlDigestAlgoAndValue xmlDigestAlgoAndValue) {
		return getDigestAlgAndValueType(xmlDigestAlgoAndValue.getDigestMethod(), xmlDigestAlgoAndValue.getDigestValue());
	}
	
	private DigestAlgAndValueType getDigestAlgAndValueType(DigestAlgorithm digestAlgo, byte[] digestValue) {
		DigestAlgAndValueType digestAlgAndValueType = new DigestAlgAndValueType();
		DigestMethodType digestMethodType = new DigestMethodType();
		digestMethodType.setAlgorithm(digestAlgo.getUri());
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
		validationObject.setValidationObjectRepresentation(representation);
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
		List<String> timestampedSignatureIds = timestamp.getTimestampedSignatureIds();
		for (String signatureId : timestampedSignatureIds) {
			SignatureWrapper timestampedSignature = diagnosticData.getSignatureById(signatureId);
			poeProvisioning.getSignatureReference().add(getSignatureReference(timestampedSignature));
		}
		return poeProvisioning;
	}
	
	private SignatureReferenceType getSignatureReference(SignatureWrapper signature) {
		SignatureReferenceType signatureReference = objectFactory.createSignatureReferenceType();
		XmlSignatureDigestReference signatureDigestReference = signature.getSignatureDigestReference();
		if (signatureDigestReference != null) {
			signatureReference.setCanonicalizationMethod(signatureDigestReference.getCanonicalizationMethod());
			signatureReference.setDigestMethod(signatureDigestReference.getDigestMethod().getUri());
			signatureReference.setDigestValue(signatureDigestReference.getDigestValue());
		} else if (signature.getSignatureFieldName() != null) {
			signatureReference.setPAdESFieldName(signature.getSignatureFieldName());
		}
		return signatureReference;
	}
	
	private void addSignerData(ValidationObjectListType validationObjectListType, XmlSignerData signedData, POEExtraction poeExtraction) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(signedData.getId());
		validationObject.setObjectType(ObjectType.SIGNED_DATA);
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		representation.setDigestAlgAndValue(getDigestAlgAndValueType(signedData.getDigestAlgoAndValue()));
		validationObject.setValidationObjectRepresentation(representation);
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
		validationObject.setValidationObjectRepresentation(representation);
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
		validationObject.setValidationObjectRepresentation(representation);
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
				validationStatus.getSubIndication().add(subIndication);
			}
		}

		addValidationReportData(validationStatus, signature);
		return validationStatus;
	}

	private void fillIndication(ValidationStatusType validationStatus, Indication indication) {
		switch (indication) {
		case PASSED:
			validationStatus.setMainIndication(Indication.TOTAL_PASSED);
			break;
		case FAILED:
			validationStatus.setMainIndication(Indication.TOTAL_FAILED);
			break;
		case INDETERMINATE:
			validationStatus.setMainIndication(Indication.INDETERMINATE);
			break;
		default:
			throw new IllegalArgumentException("Unsupported indication : " + indication);
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
			validationStatus.setMainIndication(indication);
		}
		if (subIndication != null) {
			validationStatus.getSubIndication().add(subIndication);
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
			revocationStatusInformationType.setRevocationReason(revocationInfo.getReason());
		}
		validationReportData.setRevocationStatusInformation(revocationStatusInformationType);
	}

	private void fillCertificateChainAndTrustAnchor(ValidationReportDataType validationReportData, XmlCertificateChain certificateChain) {
		List<XmlChainItem> chainItem = certificateChain.getChainItem();
		if (Utils.isCollectionEmpty(chainItem)) {
			return;
		}

		CertificateChainType certificateChainType = objectFactory.createCertificateChainType();
		VOReferenceType signingCert = null;
		VOReferenceType trustAnchor = null;
		for (int i = 0; i < chainItem.size(); i++) {
			XmlChainItem currentChainItem = chainItem.get(i);
			VOReferenceType currentVORef = getVOReference(currentChainItem.getId());
			CertificateSourceType source = currentChainItem.getSource();

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

	private boolean isTrustAnchor(CertificateSourceType source) {
		return CertificateSourceType.TRUSTED_LIST.equals(source) || CertificateSourceType.TRUSTED_STORE.equals(source);
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
						xmlDigestMatcher.getDigestMethod() != null && Utils.isArrayNotEmpty(xmlDigestMatcher.getDigestValue())) {
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
		List<String> certIds = sigWrapper.getFoundCertificateIds(CertificateOrigin.ATTR_AUTORITIES_CERT_VALUES);
		if (Utils.isCollectionNotEmpty(certIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttrAuthoritiesCertValues(buildTokenList(certIds)));
		}
	}

	private void addTimeStampValidationData(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> refIds = sigWrapper.getFoundCertificateIds(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
		refIds.addAll(sigWrapper.getRevocationIdsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA));
		if (Utils.isCollectionNotEmpty(refIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeTimeStampValidationData(buildTokenList(refIds)));
		}
	}

	private void addCertificateValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> certIds = sigWrapper.getFoundCertificateIds(CertificateOrigin.CERTIFICATE_VALUES);
		if (Utils.isCollectionNotEmpty(certIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCertificateValues(buildTokenList(certIds)));
		}
	}

	private void addAttributeCertificateRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);
		if (Utils.isCollectionNotEmpty(certs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttributeCertificateRefs(buildCertIDListType(certs)));
		}
	}

	private void addCompleteCertificateRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		if (Utils.isCollectionNotEmpty(certs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCompleteCertificateRefs(buildCertIDListType(certs)));
		}
	}

	private void addSigningCertificate(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
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
					certIDType.setDigestMethod(getDigestMethodType(digestAlgoAndValue));
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
		List<XmlRevocationRef> revocationRefs = sigWrapper.getFoundRevocationRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
				.add(objectFactory.createSignatureAttributesTypeCompleteRevocationRefs(buildRevIDListType(revocationRefs)));
		}
	}
	
	private void addAttributeRevocationRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlRevocationRef> revocationRefs = sigWrapper.getFoundRevocationRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
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
				XmlDigestAlgoAndValue digestAlgoAndValue = xmlRevocationRef.getDigestAlgoAndValue();
				sacrlidType.setDigestMethod(getDigestMethodType(digestAlgoAndValue));
				sacrlidType.setDigestValue(digestAlgoAndValue.getDigestValue());
				revIDListType.getCRLIDOrOCSPID().add(sacrlidType);
			} else {
				SAOCSPIDType ocspID = getOCSPID(xmlRevocationRef);
				if (ocspID != null) {
					revIDListType.getCRLIDOrOCSPID().add(ocspID);
				}
			}
		}

		return revIDListType;
	}

	private DigestMethodType getDigestMethodType(XmlDigestAlgoAndValue digestAlgoAndValue) {
		DigestMethodType digestMethodType = new DigestMethodType();
		digestMethodType.setAlgorithm(digestAlgoAndValue.getDigestMethod().getUri());
		return digestMethodType;
	}

	private SAOCSPIDType getOCSPID(XmlRevocationRef xmlRevocationRef) {
		if (Utils.isStringNotEmpty(xmlRevocationRef.getResponderIdName()) || Utils.isArrayNotEmpty(xmlRevocationRef.getResponderIdKey())) {
			SAOCSPIDType saocspidType = objectFactory.createSAOCSPIDType();
			saocspidType.setProducedAt(xmlRevocationRef.getProducedAt());
			if (Utils.isStringNotEmpty(xmlRevocationRef.getResponderIdName())) {
				saocspidType.setResponderIDByName(xmlRevocationRef.getResponderIdName());
			} else {
				saocspidType.setResponderIDByKey(xmlRevocationRef.getResponderIdKey());
			}
			return saocspidType;
		}
		return null;
	}
	
	private void addRevocationValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> revocationRefs = sigWrapper.getRevocationIdsByOrigin(RevocationOrigin.REVOCATION_VALUES);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeRevocationValues(buildTokenList(revocationRefs)));
		}
	}
	
	private void addAttributeRevocationValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> revocationRefs = sigWrapper.getRevocationIdsByOrigin(RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttributeRevocationValues(buildTokenList(revocationRefs)));
		}
	}

	private void addMessageDigest(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		XmlDigestMatcher messageDigest = sigWrapper.getMessageDigest();
		if (messageDigest != null && messageDigest.getDigestValue() != null) {
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

		boolean isSigned = sigWrapper.isBLevelTechnicallyValid() && timestampType.isContentTimestamp();

		for (TimestampWrapper timestampWrapper : timestampListByType) {
			SATimestampType timestamp = getSATimestampType(timestampWrapper);
			JAXBElement<SATimestampType> wrap = wrap(timestampType, timestamp);
			if (isSigned) {
				wrap.getValue().setSigned(isSigned);
			}
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(wrap);
		}
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
			throw new IllegalArgumentException("Unsupported timestamp type " + timestampType);
		}
	}

	private JAXBElement<SATimestampType> wrap(TimestampLocation timestampLocation, SATimestampType timestamp) {
		switch (timestampLocation) {
			case DOC_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeDocTimeStamp(timestamp);
			default:
			throw new IllegalArgumentException("Unsupported timestamp type " + timestampLocation);
		}
	}
	
	private void addSigPolicyIdentifier(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String policyId = sigWrapper.getPolicyId();
		if (Utils.isStringNotEmpty(policyId) && // exclude empty and default values
				!SignaturePolicyType.IMPLICIT_POLICY.name().equals(policyId)) {
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
		List<XmlSignerRole> signerRoles = sigWrapper.getSignerRoles();
		if (Utils.isCollectionNotEmpty(signerRoles)) {
			SASignerRoleType signerRoleType = objectFactory.createSASignerRoleType();
			for (XmlSignerRole role : signerRoles) {
				SAOneSignerRoleType oneSignerRole = objectFactory.createSAOneSignerRoleType();
				oneSignerRole.setRole(role.getRole());
				oneSignerRole.setEndorsementType(role.getCategory());
				signerRoleType.getRoleDetails().add(oneSignerRole);
			}
			setSignedIfValid(sigWrapper, signerRoleType);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeSignerRole(signerRoleType));
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

			if (Utils.areAllStringsEmpty(address, city, stateOrProvince, postalCode, countryName)) { 
				return;
			}
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
		List<String> certIds = sigWrapper.getFoundCertificateIds(CertificateOrigin.DSS_DICTIONARY);
		List<String> crlIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY);
		List<String> ocspIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY);
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
		List<String> certIds = sigWrapper.getFoundCertificateIds(CertificateOrigin.VRI_DICTIONARY);
		List<String> crlIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.VRI_DICTIONARY);
		List<String> ocspIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.VRI_DICTIONARY);

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
