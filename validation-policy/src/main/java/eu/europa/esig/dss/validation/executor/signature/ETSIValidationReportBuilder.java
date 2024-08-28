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
package eu.europa.esig.dss.validation.executor.signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.detailedreport.jaxb.XmlChainItem;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicAlgorithm;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationInformation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.OrphanCertificateTokenWrapper;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MessageType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignaturePolicyType;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.BasicBuildingBlockDefinition;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.vpfswatsp.EvidenceRecordPOE;
import eu.europa.esig.dss.validation.process.vpfswatsp.POE;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.TimestampPOE;
import eu.europa.esig.validationreport.enums.ConstraintStatus;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.SignatureValidationProcessID;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.AdditionalValidationReportDataType;
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
import eu.europa.esig.validationreport.jaxb.TypedDataType;
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

import javax.xml.bind.JAXBElement;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds the ETSI Validation report
 */
public class ETSIValidationReportBuilder {

	/** The objet factory to use */
	private final ObjectFactory objectFactory = new ObjectFactory();

	/** The validation time */
	private final Date currentTime;

	/** The diagnostic data */
	private final DiagnosticData diagnosticData;

	 /** The detailed report */
	private final DetailedReport detailedReport;

	/** Map between signature Ids and the respective {@code SignatureIdentifierType}s */
	private final Map<String, SignatureIdentifierType> signatureIdentifierMap = new HashMap<>();

	/** Map between token Ids and the respective {@code ValidationObjectType}s */
	private final Map<String, ValidationObjectType> validationObjectMap = new HashMap<>();

	/**
	 * Default constructor
	 *
	 * @param currentTime {@link Date} validation time
	 * @param diagnosticData {@link DiagnosticData}
	 * @param detailedReport {@link DetailedReport}
	 */
	public ETSIValidationReportBuilder(Date currentTime, DiagnosticData diagnosticData, DetailedReport detailedReport) {
		this.currentTime = currentTime;
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
	}

	/**
	 * Builds {@code ValidationReportType}
	 *
	 * @return {@link ValidationReportType}
	 */
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
		signatureValidationReport.setSignersDocument(getSignersDocument(sigWrapper));
		SignatureAttributesType signatureAttributes = getSignatureAttributes(sigWrapper);
		if (!signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().isEmpty()) {
			signatureValidationReport.setSignatureAttributes(signatureAttributes);
		}
		signatureValidationReport.setSignerInformation(getSignerInformation(sigWrapper));
		signatureValidationReport.setSignatureQuality(getSignatureQuality(sigWrapper));
		signatureValidationReport.setSignatureValidationProcess(getSignatureValidationProcess(sigWrapper));
		signatureValidationReport.setSignatureValidationStatus(getValidationStatus(sigWrapper));
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

	private ValidationConstraintsEvaluationReportType getValidationConstraintsEvaluationReport(AbstractTokenProxy token) {
		ValidationConstraintsEvaluationReportType validationConstraintsEvaluationReport = objectFactory.createValidationConstraintsEvaluationReportType();
		XmlBasicBuildingBlocks bbbResults = detailedReport.getBasicBuildingBlockById(token.getId());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.FORMAT_CHECKING, bbbResults.getFC());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.IDENTIFICATION_OF_THE_SIGNING_CERTIFICATE, bbbResults.getISC());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.VALIDATION_CONTEXT_INITIALIZATION, bbbResults.getVCI());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.CRYPTOGRAPHIC_VERIFICATION, bbbResults.getCV());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.SIGNATURE_ACCEPTANCE_VALIDATION, bbbResults.getSAV());
		addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.X509_CERTIFICATE_VALIDATION, bbbResults.getXCV());
		if (token instanceof SignatureWrapper || token instanceof TimestampWrapper) {
			addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.PAST_SIGNATURE_VALIDATION, bbbResults.getPSV());
			addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.PAST_CERTIFICATE_VALIDATION, bbbResults.getPCV());
			addBBB(validationConstraintsEvaluationReport, BasicBuildingBlockDefinition.VALIDATION_TIME_SLIDING, bbbResults.getVTS());
		}
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
		XmlBasicBuildingBlocks tokenBBB = detailedReport.getBasicBuildingBlockById(token.getId());
		// return null if validation was not performed
		if (tokenBBB == null) {
			return null;
		}
		SignatureValidationReportType signatureValidationReport = objectFactory.createSignatureValidationReportType();
		signatureValidationReport.setSignerInformation(getSignerInformation(token));
		signatureValidationReport.setSignatureValidationStatus(getValidationStatus(token));
		signatureValidationReport.setValidationConstraintsEvaluationReport(getValidationConstraintsEvaluationReport(token));

		TimestampQualification timestampQualification = detailedReport.getTimestampQualification(token.getId());
		if (timestampQualification != null) {
			SignatureQualityType signatureQualityType = objectFactory.createSignatureQualityType();
			signatureQualityType.getSignatureQualityInformation().add(timestampQualification.getUri());
			signatureValidationReport.setSignatureQuality(signatureQualityType);
		}

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
			TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampId);
			if (timestampWrapper != null) {
				poeType.setPOEObject(getVOReference(getTimestampValidationObject(timestampWrapper)));
			}
			EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecordById(timestampId);
			if (evidenceRecordWrapper != null) {
				poeType.setPOEObject(getVOReference(getEvidenceRecordValidationObject(evidenceRecordWrapper)));
			}
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
		signerInfo.setSignerCertificate(getVOReference(getCertificateValidationObject(signingCert)));
		return signerInfo;
	}
	
	private XmlStatus getPseudoUseStatus(AbstractTokenProxy token) {
		XmlSubXCV signingCertificateXCV = detailedReport.getSigningCertificate(token.getId());
		if (signingCertificateXCV != null) {
			List<XmlConstraint> constraints = signingCertificateXCV.getConstraint();
			for (XmlConstraint xmlConstraint : constraints) {
				if ("BBB_XCV_PSEUDO_USE".equals(xmlConstraint.getName().getKey())) {
					return xmlConstraint.getStatus();
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

	private VOReferenceType getVOReference(SignatureIdentifierType signatureIdentifier) {
		VOReferenceType voRef = objectFactory.createVOReferenceType();
		voRef.getVOReference().add(signatureIdentifier);
		return voRef;
	}

	private VOReferenceType getVOReference(ValidationObjectType validationObject) {
		return getVOReference(Collections.singletonList(validationObject));
	}

	private VOReferenceType getVOReference(List<ValidationObjectType> validationObjects) {
		VOReferenceType voRef = objectFactory.createVOReferenceType();
		for (ValidationObjectType validationObject : validationObjects) {
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
		poeExtraction.init(diagnosticData, currentTime);

		// 1. Extract POEs
		List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
		for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
			if (Indication.PASSED == detailedReport.getEvidenceRecordValidationIndication(evidenceRecord.getId())) {
				poeExtraction.extractPOE(evidenceRecord);
			}
		}

		List<TimestampWrapper> timestampList = diagnosticData.getNonEvidenceRecordTimestamps();
		poeExtraction.collectAllPOE(timestampList);

		// 2. Add validation object types
		for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
			ValidationObjectType evidenceRecordValidationObject = getEvidenceRecordValidationObject(evidenceRecord);
			evidenceRecordValidationObject.setPOE(getPOE(evidenceRecord.getId(), poeExtraction));
			validationObjectListType.getValidationObject().add(evidenceRecordValidationObject);
		}

		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			ValidationObjectType timestampValidationObject = getTimestampValidationObject(timestamp);
			timestampValidationObject.setPOE(getPOE(timestamp.getId(), poeExtraction));
			validationObjectListType.getValidationObject().add(timestampValidationObject);
		}

		for (CertificateWrapper certificate : diagnosticData.getUsedCertificates()) {
			ValidationObjectType certificateValidationObject = getCertificateValidationObject(certificate);
			certificateValidationObject.setPOE(getPOE(certificate.getId(), poeExtraction));
			validationObjectListType.getValidationObject().add(certificateValidationObject);
		}
		
		for (OrphanCertificateTokenWrapper orphanCertificate : diagnosticData.getAllOrphanCertificateObjects()) {
			ValidationObjectType orphanCertificateValidationObject = getOrphanCertificateValidationObject(orphanCertificate);
			orphanCertificateValidationObject.setPOE(getPOE(orphanCertificate.getId(), poeExtraction));
			validationObjectListType.getValidationObject().add(orphanCertificateValidationObject);
		}

		for (RevocationWrapper revocationData : diagnosticData.getAllRevocationData()) {
			ValidationObjectType revocationValidationObject = getRevocationValidationObject(revocationData);
			revocationValidationObject.setPOE(getPOE(revocationData.getId(), poeExtraction));
			validationObjectListType.getValidationObject().add(revocationValidationObject);
		}
		
		for (OrphanRevocationTokenWrapper orphanRevocation : diagnosticData.getAllOrphanRevocationObjects()) {
			ValidationObjectType orphanRevocationValidationObject = getOrphanRevocationValidationObject(orphanRevocation);
			orphanRevocationValidationObject.setPOE(getPOE(orphanRevocation.getId(), poeExtraction));
			validationObjectListType.getValidationObject().add(orphanRevocationValidationObject);
		}

		for (SignerDataWrapper signedData : diagnosticData.getAllSignerDocuments()) {
			ValidationObjectType signerDataValidationObject = getSignerDataValidationObject(signedData);
			signerDataValidationObject.setPOE(getPOE(signedData.getId(), poeExtraction));
			validationObjectListType.getValidationObject().add(signerDataValidationObject);
		}

		return validationObjectListType;
	}

	private ValidationObjectType getCertificateValidationObject(CertificateWrapper certificate) {
		ValidationObjectType validationObject = validationObjectMap.get(certificate.getId());
		if (validationObject == null) {
			validationObject = objectFactory.createValidationObjectType();
			validationObjectMap.put(certificate.getId(), validationObject);

			validationObject.setId(certificate.getId());
			validationObject.setObjectType(ObjectType.CERTIFICATE);
			ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
			if (Utils.isArrayNotEmpty(certificate.getBinaries())) {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(certificate.getBinaries());
			} else {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(getDigestAlgAndValueType(certificate.getDigestAlgoAndValue()));
			}
			validationObject.setValidationObjectRepresentation(representation);
		}
		return validationObject;
	}
	
	private DigestAlgAndValueType getDigestAlgAndValueType(XmlDigestAlgoAndValue xmlDigestAlgoAndValue) {
		DigestAlgAndValueType digestAlgAndValueType = new DigestAlgAndValueType();
		digestAlgAndValueType.setDigestMethod(getDigestMethodType(xmlDigestAlgoAndValue.getDigestMethod()));
		digestAlgAndValueType.setDigestValue(xmlDigestAlgoAndValue.getDigestValue());
		return digestAlgAndValueType;
	}

	private String getUrn(DigestAlgorithm digestAlgorithm) {
		if (digestAlgorithm != null) {
			if (Utils.isStringNotEmpty(digestAlgorithm.getUri())) {
				return digestAlgorithm.getUri();
			}
			if (Utils.isStringNotEmpty(digestAlgorithm.getOid())) {
				return ValidationProcessUtils.toUrnOid(digestAlgorithm.getOid());
			}
		}
		return "?";
	}
	
	private POEType getPOE(String tokenId, POEExtraction poeExtraction) {
		POEType poeType = objectFactory.createPOEType();
		POE lowestPOE = poeExtraction.getLowestPOE(tokenId);
		poeType.setPOETime(lowestPOE.getTime());
		if (lowestPOE instanceof TimestampPOE) {
			String timestampId = lowestPOE.getPOEProviderId();
			if (Utils.isStringNotEmpty(timestampId)) {
				TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampId);
				poeType.setPOEObject(getVOReference(getTimestampValidationObject(timestampWrapper)));
			}
		} else if (lowestPOE instanceof EvidenceRecordPOE) {
			String evidenceRecordId = lowestPOE.getPOEProviderId();
			if (Utils.isStringNotEmpty(evidenceRecordId)) {
				EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecordById(evidenceRecordId);
				poeType.setPOEObject(getVOReference(getEvidenceRecordValidationObject(evidenceRecord)));
			}
		}
		poeType.setTypeOfProof(TypeOfProof.VALIDATION);
		return poeType;
	}

	private ValidationObjectType getEvidenceRecordValidationObject(EvidenceRecordWrapper evidenceRecord) {
		ValidationObjectType validationObject = validationObjectMap.get(evidenceRecord.getId());
		if (validationObject == null) {
			validationObject = objectFactory.createValidationObjectType();
			validationObjectMap.put(evidenceRecord.getId(), validationObject);

			validationObject.setId(evidenceRecord.getId());
			validationObject.setObjectType(ObjectType.EVIDENCE_RECORD);
			ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
			if (Utils.isArrayNotEmpty(evidenceRecord.getBinaries())) {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(evidenceRecord.getBinaries());
			} else {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(getDigestAlgAndValueType(evidenceRecord.getDigestAlgoAndValue()));
			}
			validationObject.setValidationObjectRepresentation(representation);
			validationObject.setPOEProvisioning(getPOEProvisioningType(evidenceRecord));
			validationObject.setValidationReport(getValidationReport(evidenceRecord));
		}
		return validationObject;
	}

	private POEProvisioningType getPOEProvisioningType(EvidenceRecordWrapper evidenceRecord) {
		POEProvisioningType poeProvisioning = objectFactory.createPOEProvisioningType();
		poeProvisioning.setPOETime(evidenceRecord.getFirstTimestamp().getProductionTime());

		for (CertificateWrapper cert : evidenceRecord.getCoveredCertificates()) {
			poeProvisioning.getValidationObject().add(getVOReference(getCertificateValidationObject(cert)));
		}

		// only created validation objects must be added (not references)
		List<OrphanCertificateTokenWrapper> allOrphanObjectCertificates = diagnosticData.getAllOrphanCertificateObjects();
		for (OrphanCertificateTokenWrapper orphanCert : evidenceRecord.getCoveredOrphanCertificates()) {
			if (allOrphanObjectCertificates.contains(orphanCert)) {
				poeProvisioning.getValidationObject().add(getVOReference(getOrphanCertificateValidationObject(orphanCert)));
			}
		}

		for (RevocationWrapper revocation : evidenceRecord.getCoveredRevocations()) {
			poeProvisioning.getValidationObject().add(getVOReference(getRevocationValidationObject(revocation)));
		}
		// only created validation objects must be added (not references)
		List<OrphanRevocationTokenWrapper> allOrphanObjectRevocations = diagnosticData.getAllOrphanRevocationObjects();
		for (OrphanRevocationTokenWrapper orphanRevocation : evidenceRecord.getCoveredOrphanRevocations()) {
			if (allOrphanObjectRevocations.contains(orphanRevocation)) {
				poeProvisioning.getValidationObject().add(getVOReference(getOrphanRevocationValidationObject(orphanRevocation)));
			}
		}

		for (EvidenceRecordWrapper er : evidenceRecord.getCoveredEvidenceRecords()) {
			poeProvisioning.getValidationObject().add(getVOReference(getEvidenceRecordValidationObject(er)));
		}

		for (TimestampWrapper tst : evidenceRecord.getCoveredTimestamps()) {
			poeProvisioning.getValidationObject().add(getVOReference(getTimestampValidationObject(tst)));
		}

		for (SignerDataWrapper signerData : evidenceRecord.getCoveredSignedData()) {
			poeProvisioning.getValidationObject().add(getVOReference(getSignerDataValidationObject(signerData)));
		}

		List<SignatureWrapper> timestampedSignatures = evidenceRecord.getCoveredSignatures();
		for (SignatureWrapper timestampedSignature : timestampedSignatures) {
			poeProvisioning.getSignatureReference().add(getSignatureReference(timestampedSignature));
		}

		return poeProvisioning;
	}

	private SignatureValidationReportType getValidationReport(EvidenceRecordWrapper evidenceRecord) {
		XmlEvidenceRecord xmlEvidenceRecord = detailedReport.getXmlEvidenceRecordById(evidenceRecord.getId());
		// return null if validation was not performed
		if (xmlEvidenceRecord == null) {
			return null;
		}
		SignatureValidationReportType signatureValidationReport = objectFactory.createSignatureValidationReportType();
		signatureValidationReport.setSignatureValidationStatus(getValidationStatus(evidenceRecord));
		return signatureValidationReport;
	}

	private ValidationStatusType getValidationStatus(EvidenceRecordWrapper evidenceRecord) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();
		fillIndicationSubIndication(validationStatus, evidenceRecord.getId());
		fillMessages(validationStatus, evidenceRecord.getId());
		addValidationReportData(validationStatus, evidenceRecord);
		return validationStatus;
	}

	private void addValidationReportData(ValidationStatusType validationStatus, EvidenceRecordWrapper evidenceRecord) {
		ValidationReportDataType validationReportData = getAssociatedValidationReportData(validationStatus);
		if (Indication.PASSED != detailedReport.getEvidenceRecordValidationIndication(evidenceRecord.getId())) {
			for (TimestampWrapper timestampWrapper : evidenceRecord.getTimestampList()) {
				if (Indication.PASSED != detailedReport.getFinalIndication(timestampWrapper.getId())) {
					ValidationObjectType timestampValidationObject = getTimestampValidationObject(timestampWrapper);
					validationReportData.getRelatedValidationObject().add(getVOReference(timestampValidationObject));
				}
			}
		}
		XmlEvidenceRecord xmlEvidenceRecord = detailedReport.getXmlEvidenceRecordById(evidenceRecord.getId());
		XmlValidationProcessEvidenceRecord validationProcessEvidenceRecord = xmlEvidenceRecord.getValidationProcessEvidenceRecord();
		XmlCryptographicValidation cryptographicValidation = validationProcessEvidenceRecord.getCryptographicValidation();
		if (cryptographicValidation != null) {
			fillCryptographicInfo(validationReportData, evidenceRecord, cryptographicValidation);
		}
	}
	private void fillCryptographicInfo(ValidationReportDataType validationReportData, EvidenceRecordWrapper evidenceRecord,
									   XmlCryptographicValidation cryptographicValidation) {
		CryptoInformationType cryptoInformationType = objectFactory.createCryptoInformationType();
		cryptoInformationType.setValidationObjectId(getVOReference(getEvidenceRecordValidationObject(evidenceRecord)));
		cryptoInformationType.setSecureAlgorithm(cryptographicValidation.isSecure());
		XmlCryptographicAlgorithm algorithm = cryptographicValidation.getAlgorithm();
		if (algorithm != null) {
			cryptoInformationType.setAlgorithm(algorithm.getUri());
		}
		cryptoInformationType.setNotAfter(cryptographicValidation.getNotAfter());
		validationReportData.setCryptoInformation(cryptoInformationType);
	}

	private ValidationObjectType getTimestampValidationObject(TimestampWrapper timestamp) {
		ValidationObjectType validationObject = validationObjectMap.get(timestamp.getId());
		if (validationObject == null) {
			validationObject = objectFactory.createValidationObjectType();
			validationObjectMap.put(timestamp.getId(), validationObject);

			validationObject.setId(timestamp.getId());
			validationObject.setObjectType(ObjectType.TIMESTAMP);
			ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
			if (Utils.isArrayNotEmpty(timestamp.getBinaries())) {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(timestamp.getBinaries());
			} else {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(getDigestAlgAndValueType(timestamp.getDigestAlgoAndValue()));
			}
			validationObject.setValidationObjectRepresentation(representation);
			validationObject.setPOEProvisioning(getPOEProvisioningType(timestamp));
			validationObject.setValidationReport(getValidationReport(timestamp));
		}
		return validationObject;
	}

	private POEProvisioningType getPOEProvisioningType(TimestampWrapper timestamp) {
		POEProvisioningType poeProvisioning = objectFactory.createPOEProvisioningType();
		poeProvisioning.setPOETime(timestamp.getProductionTime());
		
		for (CertificateWrapper cert : timestamp.getTimestampedCertificates()) {
			poeProvisioning.getValidationObject().add(getVOReference(getCertificateValidationObject(cert)));
		}
		// only created validation objects must be added (not references)
		List<OrphanCertificateTokenWrapper> allOrphanObjectCertificates = diagnosticData.getAllOrphanCertificateObjects();
		for (OrphanCertificateTokenWrapper orphanCert : timestamp.getTimestampedOrphanCertificates()) {
			if (allOrphanObjectCertificates.contains(orphanCert)) {
				poeProvisioning.getValidationObject().add(getVOReference(getOrphanCertificateValidationObject(orphanCert)));
			}
		}
		
		for (RevocationWrapper revocation : timestamp.getTimestampedRevocations()) {
			poeProvisioning.getValidationObject().add(getVOReference(getRevocationValidationObject(revocation)));
		}
		// only created validation objects must be added (not references)
		List<OrphanRevocationTokenWrapper> allOrphanObjectRevocations = diagnosticData.getAllOrphanRevocationObjects();
		for (OrphanRevocationTokenWrapper orphanRevocation : timestamp.getTimestampedOrphanRevocations()) {
			if (allOrphanObjectRevocations.contains(orphanRevocation)) {
				poeProvisioning.getValidationObject().add(getVOReference(getOrphanRevocationValidationObject(orphanRevocation)));
			}
		}

		for (EvidenceRecordWrapper er : timestamp.getTimestampedEvidenceRecords()) {
			poeProvisioning.getValidationObject().add(getVOReference(getEvidenceRecordValidationObject(er)));
		}
		
		for (TimestampWrapper tst : timestamp.getTimestampedTimestamps()) {
			poeProvisioning.getValidationObject().add(getVOReference(getTimestampValidationObject(tst)));
		}
		
		for (SignerDataWrapper signerData : timestamp.getTimestampedSignedData()) {
			poeProvisioning.getValidationObject().add(getVOReference(getSignerDataValidationObject(signerData)));
		}
		
		List<SignatureWrapper> timestampedSignatures = timestamp.getTimestampedSignatures();
		for (SignatureWrapper timestampedSignature : timestampedSignatures) {
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
		} else if (signature.getFirstFieldName() != null) {
			signatureReference.setPAdESFieldName(signature.getFirstFieldName());
		}
		return signatureReference;
	}

	private ValidationObjectType getSignerDataValidationObject(SignerDataWrapper signedData) {
		ValidationObjectType validationObject = validationObjectMap.get(signedData.getId());
		if (validationObject == null) {
			validationObject = objectFactory.createValidationObjectType();
			validationObjectMap.put(signedData.getId(), validationObject);

			validationObject.setId(signedData.getId());
			validationObject.setObjectType(ObjectType.SIGNED_DATA);
			ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
			representation.getDirectOrBase64OrDigestAlgAndValue().add(getDigestAlgAndValueType(signedData.getDigestAlgoAndValue()));
			validationObject.setValidationObjectRepresentation(representation);
		}
		return validationObject;
	}

	private ValidationObjectType getRevocationValidationObject(RevocationWrapper revocationData) {
		ValidationObjectType validationObject = validationObjectMap.get(revocationData.getId());
		if (validationObject == null) {
			validationObject = objectFactory.createValidationObjectType();
			validationObjectMap.put(revocationData.getId(), validationObject);

			validationObject.setId(revocationData.getId());
			if (RevocationType.CRL.equals(revocationData.getRevocationType())) {
				validationObject.setObjectType(ObjectType.CRL);
			} else {
				validationObject.setObjectType(ObjectType.OCSP_RESPONSE);
			}
			ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
			if (Utils.isArrayNotEmpty(revocationData.getBinaries())) {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(revocationData.getBinaries());
			} else {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(getDigestAlgAndValueType(revocationData.getDigestAlgoAndValue()));
			}
//		Standard says choice
//		String sourceAddress = revocationData.getSourceAddress();
//		if (Utils.isStringNotEmpty(sourceAddress)) {
//			representation.setURI(sourceAddress);
//		}
			validationObject.setValidationObjectRepresentation(representation);
			validationObject.setValidationReport(getValidationReport(revocationData));
		}
		return validationObject;
	}

	private ValidationObjectType getOrphanCertificateValidationObject(OrphanCertificateTokenWrapper orphanCertificate) {
		return createOrphanToken(orphanCertificate, ObjectType.CERTIFICATE);
	}

	private ValidationObjectType getOrphanRevocationValidationObject(OrphanRevocationTokenWrapper orphanRevocation) {
		ObjectType objectType = RevocationType.CRL.equals(orphanRevocation.getRevocationType()) ? ObjectType.CRL : ObjectType.OCSP_RESPONSE;
		return createOrphanToken(orphanRevocation, objectType);
	}
	
	private ValidationObjectType createOrphanToken(OrphanTokenWrapper<?> orphanToken, ObjectType objectType) {
		ValidationObjectType validationObject = validationObjectMap.get(orphanToken.getId());
		if (validationObject == null) {
			validationObject = objectFactory.createValidationObjectType();
			validationObjectMap.put(orphanToken.getId(), validationObject);

			validationObject.setId(orphanToken.getId());
			validationObject.setObjectType(objectType);
			ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
			if (Utils.isArrayNotEmpty(orphanToken.getBinaries())) {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(orphanToken.getBinaries());
			} else {
				representation.getDirectOrBase64OrDigestAlgAndValue().add(getDigestAlgAndValueType(orphanToken.getDigestAlgoAndValue()));
			}
			validationObject.setValidationObjectRepresentation(representation);
		}
		return validationObject;
	}

	private ValidationStatusType getValidationStatus(AbstractTokenProxy token) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();
		fillIndicationSubIndication(validationStatus, token.getId());
		fillMessages(validationStatus, token.getId());
		addValidationReportData(validationStatus, token);
		return validationStatus;
	}

	private void fillIndicationSubIndication(ValidationStatusType validationStatus, String tokenId) {
		validationStatus.setMainIndication(detailedReport.getFinalIndication(tokenId));
		validationStatus.getSubIndication().add(detailedReport.getFinalSubIndication(tokenId));
	}

	private void fillMessages(ValidationStatusType validationStatus, String tokenId) {
		fillMessagesOfType(validationStatus, detailedReport.getAdESValidationErrors(tokenId).stream()
				.map(Message::getValue).collect(Collectors.toList()), MessageType.ERROR);
		fillMessagesOfType(validationStatus, detailedReport.getAdESValidationWarnings(tokenId).stream()
				.map(Message::getValue).collect(Collectors.toList()), MessageType.WARN);
		fillMessagesOfType(validationStatus, detailedReport.getAdESValidationInfos(tokenId).stream()
				.map(Message::getValue).collect(Collectors.toList()), MessageType.INFO);
	}

	private ValidationStatusType getValidationStatus(XmlConclusion conclusion) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();
		fillIndicationSubIndication(validationStatus, conclusion);
		fillMessages(validationStatus, conclusion);
		return validationStatus;
	}

	private void fillIndicationSubIndication(ValidationStatusType validationStatus, XmlConclusion conclusion) {
		if (conclusion.getIndication() != null) {
			validationStatus.setMainIndication(conclusion.getIndication());
		}
		if (conclusion.getSubIndication() != null) {
			validationStatus.getSubIndication().add(conclusion.getSubIndication());
		}
	}

	private void fillMessages(ValidationStatusType validationStatus, XmlConclusion conclusion) {
		fillMessagesOfType(validationStatus, conclusion.getErrors().stream()
				.map(XmlMessage::getValue).collect(Collectors.toList()), MessageType.ERROR);
		fillMessagesOfType(validationStatus, conclusion.getWarnings().stream()
				.map(XmlMessage::getValue).collect(Collectors.toList()), MessageType.WARN);
		fillMessagesOfType(validationStatus, conclusion.getInfos().stream()
				.map(XmlMessage::getValue).collect(Collectors.toList()), MessageType.INFO);
	}

	private void fillMessagesOfType(ValidationStatusType validationStatus, List<String> messages, MessageType level) {
		if (Utils.isCollectionNotEmpty(messages)) {
			final ValidationReportDataType validationReportData = getAssociatedValidationReportData(validationStatus);
			AdditionalValidationReportDataType additionalValidationReportData = getAdditionalValidationReportData(validationReportData);
			for (String message : messages) {
				TypedDataType reportData = objectFactory.createTypedDataType();
				reportData.setType(level.getUri());
				reportData.setValue(message);
				additionalValidationReportData.getReportData().add(reportData);
			}
		}
	}

	private ValidationReportDataType getAssociatedValidationReportData(ValidationStatusType validationStatus) {
		List<ValidationReportDataType> associatedValidationReportData = validationStatus.getAssociatedValidationReportData();
		if (Utils.isCollectionNotEmpty(associatedValidationReportData)) {
			// only one is used
			return associatedValidationReportData.get(0);
		}
		ValidationReportDataType validationReportData = objectFactory.createValidationReportDataType();
		associatedValidationReportData.add(validationReportData);
		return validationReportData;
	}
	
	private AdditionalValidationReportDataType getAdditionalValidationReportData(ValidationReportDataType validationReportData) {
		AdditionalValidationReportDataType additionalValidationReportData = validationReportData.getAdditionalValidationReportData();
		if (additionalValidationReportData == null) {
			additionalValidationReportData = objectFactory.createAdditionalValidationReportDataType();
			validationReportData.setAdditionalValidationReportData(additionalValidationReportData);
		}
		return additionalValidationReportData;
	}

	private void addValidationReportData(ValidationStatusType validationStatus, AbstractTokenProxy token) {
		XmlBasicBuildingBlocks basicBuildingBlock = detailedReport.getBasicBuildingBlockById(token.getId());
		XmlSubXCV signingCertificate = detailedReport.getSigningCertificate(token.getId());

		if (basicBuildingBlock != null || signingCertificate != null) {
			final ValidationReportDataType validationReportData = getAssociatedValidationReportData(validationStatus);
			if (basicBuildingBlock != null) {
				XmlCertificateChain certificateChain = basicBuildingBlock.getCertificateChain();
				if (certificateChain != null) {
					fillCertificateChainAndTrustAnchor(validationReportData, certificateChain);
				}
				XmlSAV sav = basicBuildingBlock.getSAV();
				if (sav != null && sav.getCryptographicValidation() != null) {
					fillCryptographicInfo(validationReportData, token, sav.getCryptographicValidation());
				}
			}
			if (signingCertificate != null && signingCertificate.getRevocationInfo() != null) {
				fillRevocationInfo(validationReportData, signingCertificate.getRevocationInfo());
			}
		}
	}

	private void fillCryptographicInfo(ValidationReportDataType validationReportData, AbstractTokenProxy token, XmlCryptographicValidation cryptographicValidation) {
		CryptoInformationType cryptoInformationType = objectFactory.createCryptoInformationType();
		if (token instanceof SignatureWrapper) {
			cryptoInformationType.setValidationObjectId(getVOReference(getSignatureIdentifier((SignatureWrapper) token)));
		} else if (token instanceof TimestampWrapper) {
			cryptoInformationType.setValidationObjectId(getVOReference(getTimestampValidationObject((TimestampWrapper) token)));
		} else if (token instanceof RevocationWrapper) {
			cryptoInformationType.setValidationObjectId(getVOReference(getRevocationValidationObject((RevocationWrapper) token)));
		} else {
			throw new IllegalArgumentException(String.format("Unsupported class %s", token.getClass()));
		}
		cryptoInformationType.setSecureAlgorithm(cryptographicValidation.isSecure());
		XmlCryptographicAlgorithm algorithm = cryptographicValidation.getAlgorithm();
		if (algorithm != null) {
			cryptoInformationType.setAlgorithm(algorithm.getUri());
		}
		cryptoInformationType.setNotAfter(cryptographicValidation.getNotAfter());
		validationReportData.setCryptoInformation(cryptoInformationType);
	}

	private void fillRevocationInfo(ValidationReportDataType validationReportData, XmlRevocationInformation revocationInfo) {
		RevocationStatusInformationType revocationStatusInformationType = objectFactory.createRevocationStatusInformationType();
		revocationStatusInformationType.setRevocationTime(revocationInfo.getRevocationDate());
		RevocationWrapper revocationWrapper = diagnosticData.getRevocationById(revocationInfo.getRevocationId());
		revocationStatusInformationType.setRevocationObject(getVOReference(getRevocationValidationObject(revocationWrapper)));
		CertificateWrapper certificateWrapper = diagnosticData.getCertificateById(revocationInfo.getCertificateId());
		revocationStatusInformationType.setValidationObjectId(getVOReference(getCertificateValidationObject(certificateWrapper)));
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
			CertificateWrapper certificateWrapper = diagnosticData.getCertificateById(currentChainItem.getId());
			VOReferenceType currentVORef = getVOReference(getCertificateValidationObject(certificateWrapper));
			CertificateSourceType source = currentChainItem.getSource();

			boolean isSigningCert = (i == 0);
			boolean isTrustAnchor = isTrustAnchor(source);

			if (isSigningCert || isTrustAnchor) {
				if (isSigningCert) {
					signingCert = currentVORef;
				}
				if (isTrustAnchor) {
					trustAnchor = currentVORef;
					// Stops with the first found trust anchor
					break;
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
		SignatureIdentifierType signatureIdentifier = signatureIdentifierMap.get(sigWrapper.getId());
		if (signatureIdentifier == null) {
			signatureIdentifier = objectFactory.createSignatureIdentifierType();
			signatureIdentifierMap.put(sigWrapper.getId(), signatureIdentifier);

			signatureIdentifier.setId(sigWrapper.getId());
			signatureIdentifier.setDAIdentifier(sigWrapper.getDAIdentifier());
			signatureIdentifier.setDocHashOnly(sigWrapper.isDocHashOnly());
			signatureIdentifier.setHashOnly(sigWrapper.isHashOnly());
			signatureIdentifier.setDigestAlgAndValue(getDTBSRDigestAlgAndValue(sigWrapper));
			SignatureValueType sigValue = new SignatureValueType();
			sigValue.setValue(sigWrapper.getSignatureValue());
			signatureIdentifier.setSignatureValue(sigValue);
		}
		return signatureIdentifier;
	}
	
	private DigestAlgAndValueType getDTBSRDigestAlgAndValue(SignatureWrapper sigWrapper) {
		XmlDigestAlgoAndValue dtbsr = sigWrapper.getDataToBeSignedRepresentation();
		if (dtbsr != null) {
			return getDigestAlgAndValueType(sigWrapper.getDataToBeSignedRepresentation());
		}
		return null;
	}
	
	private SignersDocumentType getSignersDocument(SignatureWrapper sigWrapper) {
		List<SignerDataWrapper> signerDocuments = diagnosticData.getSignerDocuments(sigWrapper.getId());
		if (Utils.isCollectionEmpty(signerDocuments)) {
			return null;
		}

		SignersDocumentType signersDocumentType = objectFactory.createSignersDocumentType();
		if (Utils.collectionSize(signerDocuments) == 1) {
			SignerDataWrapper signerDocument = signerDocuments.get(0);
			DigestAlgAndValueType digestAlgAndValueType = getDigestAlgAndValueType(signerDocument.getDigestAlgoAndValue());
			signersDocumentType.getContent().add(objectFactory.createSignersDocumentTypeDigestAlgAndValue(digestAlgAndValueType));
		}

		final List<ValidationObjectType> validationObjectList = new ArrayList<>();

		List<XmlSignatureScope> signatureScopes = sigWrapper.getSignatureScopes();
		List<SignerDataWrapper> signerDataList = signatureScopes.stream().map(s -> new SignerDataWrapper(s.getSignerData())).collect(Collectors.toList());
		for (SignerDataWrapper signerDataWrapper : signerDataList) {
			validationObjectList.add(getSignerDataValidationObject(signerDataWrapper));
		}

		signersDocumentType.getContent().add(objectFactory.createSignersDocumentTypeSignersDocumentRepresentation(
				getVOReference(validationObjectList)));

		return signersDocumentType;
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
		addCompleteCertificateRefs(sigAttributes, sigWrapper.foundCertificates());
		// &lt;element name="CompleteRevocationRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SARevIDListType"/&gt;
		addCompleteRevocationRefs(sigAttributes, sigWrapper.foundRevocations());
		// &lt;element name="AttributeCertificateRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		addAttributeCertificateRefs(sigAttributes, sigWrapper.foundCertificates());
		// &lt;element name="AttributeRevocationRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SARevIDListType"/&gt;
		addAttributeRevocationRefs(sigAttributes, sigWrapper.foundRevocations());
		// &lt;element name="SigAndRefsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.VALIDATION_DATA_TIMESTAMP);
		// &lt;element name="RefsOnlyTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		// &lt;element name="CertificateValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addCertificateValues(sigAttributes, sigWrapper.foundCertificates());
		// &lt;element name="RevocationValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addRevocationValues(sigAttributes, sigWrapper.foundRevocations());
		// &lt;element name="AttrAuthoritiesCertValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addAttrAuthoritiesCertValues(sigAttributes, sigWrapper.foundCertificates());
		// &lt;element name="AttributeRevocationValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addAttributeRevocationValues(sigAttributes, sigWrapper.foundRevocations());
		// &lt;element name="TimeStampValidationData" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		addTimeStampValidationData(sigAttributes, sigWrapper.foundCertificates(), sigWrapper.foundRevocations());
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
		addTimestampsByType(sigAttributes, sigWrapper, TimestampType.DOCUMENT_TIMESTAMP);
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

	private void addAttrAuthoritiesCertValues(SignatureAttributesType sigAttributes, FoundCertificatesProxy foundCertificates) {
		List<ValidationObjectType> validationObjectTypes = new ArrayList<>();
		for (CertificateWrapper certificateWrapper : foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES)) {
			validationObjectTypes.add(getCertificateValidationObject(certificateWrapper));
		}
		for (OrphanCertificateTokenWrapper orphanCertificate : foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES)) {
			validationObjectTypes.add(getOrphanCertificateValidationObject(orphanCertificate));
		}
		if (Utils.isCollectionNotEmpty(validationObjectTypes)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttrAuthoritiesCertValues(buildAttributeObjectList(validationObjectTypes)));
		}
	}

	private void addTimeStampValidationData(SignatureAttributesType sigAttributes, 
			FoundCertificatesProxy foundCertificates, FoundRevocationsProxy foundRevocations) {
		List<ValidationObjectType> validationObjectTypes = new ArrayList<>();
		for (CertificateWrapper certificateWrapper : foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA)) {
			validationObjectTypes.add(getCertificateValidationObject(certificateWrapper));
		}
		for (OrphanCertificateTokenWrapper orphanCertificate : foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA)) {
			validationObjectTypes.add(getOrphanCertificateValidationObject(orphanCertificate));
		}
		for (RevocationWrapper revocationWrapper : foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA)) {
			validationObjectTypes.add(getRevocationValidationObject(revocationWrapper));
		}
		for (OrphanRevocationTokenWrapper orphanRevocation : foundRevocations.getOrphanRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA)) {
			validationObjectTypes.add(getOrphanRevocationValidationObject(orphanRevocation));
		}
		
		if (Utils.isCollectionNotEmpty(validationObjectTypes)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeTimeStampValidationData(buildAttributeObjectList(validationObjectTypes)));
		}
	}

	private void addCertificateValues(SignatureAttributesType sigAttributes, FoundCertificatesProxy foundCertificates) {
		List<ValidationObjectType> validationObjectTypes = new ArrayList<>();
		for (CertificateWrapper certificateWrapper : foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES)) {
			validationObjectTypes.add(getCertificateValidationObject(certificateWrapper));
		}
		for (OrphanCertificateTokenWrapper orphanCertificate : foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES)) {
			validationObjectTypes.add(getOrphanCertificateValidationObject(orphanCertificate));
		}
		if (Utils.isCollectionNotEmpty(validationObjectTypes)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCertificateValues(buildAttributeObjectList(validationObjectTypes)));
		}
	}

	private void addAttributeCertificateRefs(SignatureAttributesType sigAttributes, FoundCertificatesProxy foundCertificates) {
		List<RelatedCertificateWrapper> relatedCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);
		List<OrphanCertificateWrapper> orphanCerts = foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);

		if (Utils.isCollectionNotEmpty(relatedCerts) || Utils.isCollectionNotEmpty(orphanCerts)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttributeCertificateRefs(buildCertIDListType(relatedCerts, orphanCerts)));
		}
	}

	private void addCompleteCertificateRefs(SignatureAttributesType sigAttributes, FoundCertificatesProxy foundCertificates) {
		List<RelatedCertificateWrapper> relatedCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		List<OrphanCertificateWrapper> orphanCerts = foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);

		if (Utils.isCollectionNotEmpty(relatedCerts) || Utils.isCollectionNotEmpty(orphanCerts)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCompleteCertificateRefs(buildCertIDListType(relatedCerts, orphanCerts)));
		}
	}

	private void addSigningCertificate(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		FoundCertificatesProxy foundCertificates = sigWrapper.foundCertificates();
		List<RelatedCertificateWrapper> relatedCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		List<OrphanCertificateWrapper> orphanCerts = foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);

		if (Utils.isCollectionNotEmpty(relatedCerts) || Utils.isCollectionNotEmpty(orphanCerts)) {
			JAXBElement<SACertIDListType> signingCertAttribute = objectFactory.createSignatureAttributesTypeSigningCertificate(buildCertIDListType(relatedCerts, orphanCerts));
			if (sigWrapper.isBLevelTechnicallyValid()) {
				signingCertAttribute.getValue().setSigned(true);
			}
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(signingCertAttribute);
		}
	}

	private AttributeBaseType buildAttributeObjectList(List<ValidationObjectType> validationObjects) {
		AttributeBaseType attributeBaseType = objectFactory.createAttributeBaseType();
		for (ValidationObjectType validationObjectType : validationObjects) {
			attributeBaseType.getAttributeObject().add(getVOReference(Collections.singletonList(validationObjectType)));
		}
		return attributeBaseType;
	}

	private SACertIDListType buildCertIDListType(List<RelatedCertificateWrapper> relatedCerts, List<OrphanCertificateWrapper> orphanCerts) {
		SACertIDListType certIdList = objectFactory.createSACertIDListType();
		List<ValidationObjectType> validationObjects = new ArrayList<>();
		
		if (Utils.isCollectionNotEmpty(relatedCerts)) {
			for (CertificateWrapper cert : relatedCerts) {
				validationObjects.add(getCertificateValidationObject(cert));
			}
		}
		
		// The getCertID is not instantiated, because all tokens are listed in ValidationObjects
		
		// See TS 119 102-2 ch. A.3.2 XML (SigningCertificate):
		// For every certificate referenced within the reported attribute that is not present as validation object (for instance because
		// the creator of the validation report cannot gain access to it), this component shall have one CertID child.
		
		if (Utils.isCollectionNotEmpty(orphanCerts)) {
			List<OrphanCertificateTokenWrapper> allOrphanCertificates = diagnosticData.getAllOrphanCertificateObjects();
			for (OrphanCertificateWrapper orphanCert : orphanCerts) {
				if (orphanCert != null) {
					if (Utils.isCollectionNotEmpty(orphanCert.getReferences()) && !allOrphanCertificates.contains(orphanCert)) {
						for (CertificateRefWrapper certRef : orphanCert.getReferences()) {
							certIdList.getCertID().add(buildCertIDType(certRef.getDigestAlgoAndValue(), certRef.getIssuerSerial()));
						}
					} else {
						validationObjects.add(getOrphanCertificateValidationObject(orphanCert));
					}
				}
				
			}
		}
		
		if (Utils.isCollectionNotEmpty(validationObjects)) {
			certIdList.getAttributeObject().add(getVOReference(validationObjects));
		}
		
		return certIdList;
	}
	
	private SACertIDType buildCertIDType(XmlDigestAlgoAndValue digestAlgoAndValue, byte[] issuerSerial) {
		SACertIDType certIDType = objectFactory.createSACertIDType();
		certIDType.setDigestMethod(getDigestMethodType(digestAlgoAndValue.getDigestMethod()));
		certIDType.setDigestValue(digestAlgoAndValue.getDigestValue());
		if (issuerSerial != null) {
			certIDType.setX509IssuerSerial(issuerSerial);
		}
		return certIDType;
	}
	
	private void addCompleteRevocationRefs(SignatureAttributesType sigAttributes, FoundRevocationsProxy revocationsProxy) {
		List<RelatedRevocationWrapper> relatedRevs = revocationsProxy.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		List<OrphanRevocationWrapper> orphanRevs = revocationsProxy.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);

		if (Utils.isCollectionNotEmpty(relatedRevs) || Utils.isCollectionNotEmpty(orphanRevs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCompleteRevocationRefs(buildRevIDListType(relatedRevs, orphanRevs)));
		}
	}
	
	private void addAttributeRevocationRefs(SignatureAttributesType sigAttributes, FoundRevocationsProxy revocationsProxy) {
		List<RelatedRevocationWrapper> relatedRevs = revocationsProxy.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
		List<OrphanRevocationWrapper> orphanRevs = revocationsProxy.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);

		if (Utils.isCollectionNotEmpty(relatedRevs) || Utils.isCollectionNotEmpty(orphanRevs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttributeRevocationRefs(buildRevIDListType(relatedRevs, orphanRevs)));
		}
	}
	
	private SARevIDListType buildRevIDListType(List<RelatedRevocationWrapper> relatedRevs, List<OrphanRevocationWrapper> orphanRevs) {
		SARevIDListType revIDListType = objectFactory.createSARevIDListType();
		List<ValidationObjectType> validationObjects = new ArrayList<>();
		
		if (Utils.isCollectionNotEmpty(relatedRevs)) {
			for (RevocationWrapper revocation : relatedRevs) {
				validationObjects.add(getRevocationValidationObject(revocation));
			}
		}
		
		if (Utils.isCollectionNotEmpty(orphanRevs)) {
			List<OrphanRevocationTokenWrapper> allOrphanRevocations = diagnosticData.getAllOrphanRevocationObjects();
			for (OrphanRevocationWrapper orphanRev : orphanRevs) {
				if (orphanRev != null) {
					if (Utils.isCollectionNotEmpty(orphanRev.getReferences()) && !allOrphanRevocations.contains(orphanRev)) {
						for (RevocationRefWrapper revRef : orphanRev.getReferences()) {
							Serializable revID;
							if (RevocationType.CRL.equals(orphanRev.getRevocationType())) {
								revID = buildCRLID(revRef.getDigestAlgoAndValue());
							} else {
								revID = buildOCSPID(revRef);
							}
							if (revID != null) {
								revIDListType.getCRLIDOrOCSPID().add(revID);
							}
						}
					} else {
						validationObjects.add(getOrphanRevocationValidationObject(orphanRev));
					}
				}
				
			}
		}

		if (Utils.isCollectionNotEmpty(validationObjects)) {
			revIDListType.getAttributeObject().add(getVOReference(validationObjects));
		}
		
		return revIDListType;
	}
	
	private SACRLIDType buildCRLID(XmlDigestAlgoAndValue digestAlgoAndValue) {
		SACRLIDType sacrlidType = objectFactory.createSACRLIDType();
		sacrlidType.setDigestMethod(getDigestMethodType(digestAlgoAndValue.getDigestMethod()));
		sacrlidType.setDigestValue(digestAlgoAndValue.getDigestValue());
		return sacrlidType;
	}

	private SAOCSPIDType buildOCSPID(RevocationRefWrapper revRef) {
		if (Utils.isStringNotEmpty(revRef.getResponderIdName()) || Utils.isArrayNotEmpty(revRef.getResponderIdKey())) {
			SAOCSPIDType saocspidType = objectFactory.createSAOCSPIDType();
			saocspidType.setProducedAt(revRef.getProductionTime());
			if (Utils.isStringNotEmpty(revRef.getResponderIdName())) {
				saocspidType.setResponderIDByName(revRef.getResponderIdName());
			} else {
				saocspidType.setResponderIDByKey(revRef.getResponderIdKey());
			}
			return saocspidType;
		}
		return null;
	}

	private DigestMethodType getDigestMethodType(DigestAlgorithm digestAlgorithm) {
		DigestMethodType digestMethodType = new DigestMethodType();
		digestMethodType.setAlgorithm(getUrn(digestAlgorithm));
		return digestMethodType;
	}
	
	private void addRevocationValues(SignatureAttributesType sigAttributes, FoundRevocationsProxy foundRevocations) {
		List<ValidationObjectType> validationObjects = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES)) {
			validationObjects.add(getRevocationValidationObject(revocationWrapper));
		}
		for (OrphanRevocationTokenWrapper orphanRevocation : foundRevocations.getOrphanRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES)) {
			validationObjects.add(getOrphanRevocationValidationObject(orphanRevocation));
		}
		if (Utils.isCollectionNotEmpty(validationObjects)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeRevocationValues(buildAttributeObjectList(validationObjects)));
		}
	}
	
	private void addAttributeRevocationValues(SignatureAttributesType sigAttributes, FoundRevocationsProxy foundRevocations) {
		List<ValidationObjectType> validationObjects = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES)) {
			validationObjects.add(getRevocationValidationObject(revocationWrapper));
		}
		for (OrphanRevocationTokenWrapper orphanRevocation : foundRevocations.getOrphanRevocationsByOrigin(RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES)) {
			validationObjects.add(getOrphanRevocationValidationObject(orphanRevocation));
		}
		if (Utils.isCollectionNotEmpty(validationObjects)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttributeRevocationValues(buildAttributeObjectList(validationObjects)));
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
	
	private SATimestampType getSATimestampType(TimestampWrapper timestampWrapper) {
		SATimestampType timestamp = objectFactory.createSATimestampType();
		timestamp.setTimeStampValue(timestampWrapper.getProductionTime());
		timestamp.getAttributeObject().add(getVOReference(getTimestampValidationObject(timestampWrapper)));
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
			case DOCUMENT_TIMESTAMP:
				return objectFactory.createSignatureAttributesTypeDocTimeStamp(timestamp);
			default:
			throw new IllegalArgumentException("Unsupported timestamp type " + timestampType);
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
		List<XmlCommitmentTypeIndication> commitmentTypeIndications = sigWrapper.getCommitmentTypeIndications();
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {
			for (XmlCommitmentTypeIndication commitmentTypeIndication : commitmentTypeIndications) {
				SACommitmentTypeIndicationType commitmentType = objectFactory.createSACommitmentTypeIndicationType();
				commitmentType.setCommitmentTypeIdentifier(commitmentTypeIndication.getIdentifier());
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
			saCounterSignatureType.getAttributeObject().add(getVOReference(getSignatureIdentifier(counterSignature)));
			SignatureReferenceType signatureReference = getSignatureReference(counterSignature);
			saCounterSignatureType.setCounterSignature(signatureReference);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(
					objectFactory.createSignatureAttributesTypeCounterSignature(saCounterSignatureType));
		}
	}

	private void addProductionPlace(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		SASignatureProductionPlaceType sigProductionPlace = objectFactory.createSASignatureProductionPlaceType();

		/*
		 * A.9.5 PAdES
		 * 
		 * For PAdES signatures as specified in ETSI EN 319 142-1 [i.3] and ETSI EN 319
		 * 142-2 [i.4], clause 5 this component shall have the contents of the Location
		 * entry in the Signature PDF dictionary.
		 */
		if (sigWrapper.getPDFRevision() != null) {
			final String location = sigWrapper.getLocation();
			if (Utils.isStringNotEmpty(location)) {
				sigProductionPlace.getAddressString().add(location);
			} else {
				return;
			}
			/*
			 * XAdES, CAdES, JAdES
			 */
		} else if (sigWrapper.isSignatureProductionPlacePresent()) {
			final List<String> postalAddress = sigWrapper.getPostalAddress();
			final String streetAddress = sigWrapper.getStreetAddress();
			final String city = sigWrapper.getCity();
			final String stateOrProvince = sigWrapper.getStateOrProvince();
			final String postOfficeBoxNumber = sigWrapper.getPostOfficeBoxNumber();
			final String postalCode = sigWrapper.getPostalCode();
			final String countryName = sigWrapper.getCountryName();

			if (Utils.isCollectionEmpty(postalAddress) && 
					Utils.areAllStringsEmpty(streetAddress, city, stateOrProvince, 
							postOfficeBoxNumber, postalCode, countryName)) {
				return;
			}

			if (Utils.isStringNotEmpty(countryName)) {
				sigProductionPlace.getAddressString().add(countryName);
			}
			if (Utils.isStringNotEmpty(stateOrProvince)) {
				sigProductionPlace.getAddressString().add(stateOrProvince);
			}
			if (Utils.isStringNotEmpty(city)) {
				sigProductionPlace.getAddressString().add(city);
			}
			if (Utils.isStringNotEmpty(streetAddress)) {
				sigProductionPlace.getAddressString().add(streetAddress);
			}
			if (Utils.isCollectionNotEmpty(postalAddress)) {
				sigProductionPlace.getAddressString().addAll(postalAddress);
			}
			if (Utils.isStringNotEmpty(postalCode)) {
				sigProductionPlace.getAddressString().add(postalCode);
			}
			if (Utils.isStringNotEmpty(postOfficeBoxNumber)) {
				sigProductionPlace.getAddressString().add(postOfficeBoxNumber);
			}

		} else {
			return;

		}

		setSignedIfValid(sigWrapper, sigProductionPlace);
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
				.add(objectFactory.createSignatureAttributesTypeSignatureProductionPlace(sigProductionPlace));
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
		List<ValidationObjectType> certificateValidationObjects = new ArrayList<>();
		for (CertificateWrapper certificateWrapper : sigWrapper.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY)) {
			certificateValidationObjects.add(getCertificateValidationObject(certificateWrapper));
		}
		for (OrphanCertificateTokenWrapper orphanCertificate : sigWrapper.foundCertificates().getOrphanCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY)) {
			certificateValidationObjects.add(getOrphanCertificateValidationObject(orphanCertificate));
		}

		List<ValidationObjectType> crlValidationObjects = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : sigWrapper.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY)) {
			crlValidationObjects.add(getRevocationValidationObject(revocationWrapper));
		}
		for (OrphanRevocationTokenWrapper orphanRevocation : sigWrapper.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.DSS_DICTIONARY)) {
			crlValidationObjects.add(getOrphanRevocationValidationObject(orphanRevocation));
		}

		List<ValidationObjectType> ocspValidationObjects = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : sigWrapper.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY)) {
			ocspValidationObjects.add(getRevocationValidationObject(revocationWrapper));
		}
		for (OrphanRevocationTokenWrapper orphanRevocation : sigWrapper.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.DSS_DICTIONARY)) {
			ocspValidationObjects.add(getOrphanRevocationValidationObject(orphanRevocation));
		}

		if (Utils.isCollectionNotEmpty(certificateValidationObjects) || Utils.isCollectionNotEmpty(crlValidationObjects) || Utils.isCollectionNotEmpty(ocspValidationObjects)) {
			SADSSType dssType = objectFactory.createSADSSType();
			if (Utils.isCollectionNotEmpty(certificateValidationObjects)) {
				dssType.setCerts(getVOReference(certificateValidationObjects));
			}
			if (Utils.isCollectionNotEmpty(crlValidationObjects)) {
				dssType.setCRLs(getVOReference(crlValidationObjects));
			}
			if (Utils.isCollectionNotEmpty(ocspValidationObjects)) {
				dssType.setOCSPs(getVOReference(ocspValidationObjects));
			}
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeDSS(dssType));
		}
	}

	private void addVRI(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<ValidationObjectType> certificateValidationObjects = new ArrayList<>();
		for (CertificateWrapper certificateWrapper : sigWrapper.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY)) {
			certificateValidationObjects.add(getCertificateValidationObject(certificateWrapper));
		}
		for (OrphanCertificateTokenWrapper orphanCertificate : sigWrapper.foundCertificates().getOrphanCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY)) {
			certificateValidationObjects.add(getOrphanCertificateValidationObject(orphanCertificate));
		}

		List<ValidationObjectType> crlValidationObjects = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : sigWrapper.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.VRI_DICTIONARY)) {
			crlValidationObjects.add(getRevocationValidationObject(revocationWrapper));
		}
		for (OrphanRevocationTokenWrapper orphanRevocation : sigWrapper.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.VRI_DICTIONARY)) {
			crlValidationObjects.add(getOrphanRevocationValidationObject(orphanRevocation));
		}

		List<ValidationObjectType> ocspValidationObjects = new ArrayList<>();
		for (RevocationWrapper revocationWrapper : sigWrapper.foundRevocations().getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.VRI_DICTIONARY)) {
			ocspValidationObjects.add(getRevocationValidationObject(revocationWrapper));
		}
		for (OrphanRevocationTokenWrapper orphanRevocation : sigWrapper.foundRevocations().getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.VRI_DICTIONARY)) {
			ocspValidationObjects.add(getOrphanRevocationValidationObject(orphanRevocation));
		}

		if (Utils.isCollectionNotEmpty(certificateValidationObjects) || Utils.isCollectionNotEmpty(crlValidationObjects) || Utils.isCollectionNotEmpty(ocspValidationObjects)) {
			SAVRIType vriType = objectFactory.createSAVRIType();
			if (Utils.isCollectionNotEmpty(certificateValidationObjects)) {
				vriType.setCerts(getVOReference(certificateValidationObjects));
			}
			if (Utils.isCollectionNotEmpty(crlValidationObjects)) {
				vriType.setCRLs(getVOReference(crlValidationObjects));
			}
			if (Utils.isCollectionNotEmpty(ocspValidationObjects)) {
				vriType.setOCSPs(getVOReference(ocspValidationObjects));
			}
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeVRI(vriType));
		}
	}

	private void addSigningTime(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		Date signingTime = sigWrapper.getClaimedSigningTime();
		if (signingTime != null) {
			SASigningTimeType saSigningTimeType = objectFactory.createSASigningTimeType();
			saSigningTimeType.setTime(signingTime);
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
