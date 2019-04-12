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
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCryptographicInformation;
import eu.europa.esig.dss.jaxb.detailedreport.XmlProofOfExistence;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRevocationInformation;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateLocationType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignerData;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DigestMatcherType;
import eu.europa.esig.dss.validation.RevocationRefLocation;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.XmlCertificateSourceType;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
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
import eu.europa.esig.jaxb.validationreport.CryptoInformationType;
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
import eu.europa.esig.jaxb.validationreport.ValidationObjectListType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectRepresentationType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectType;
import eu.europa.esig.jaxb.validationreport.ValidationReportDataType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationStatusType;
import eu.europa.esig.jaxb.validationreport.ValidationTimeInfoType;
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
		return signatureValidationReport;
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

		String timestampId = proofOfExistence.getTimestampId();
		if (Utils.isStringNotEmpty(timestampId)) {
			poeType.setTypeOfProof(TypeOfProof.PROVIDED);
			poeType.setPOEObject(getVOReference(timestampId));
		} else {
			// Current/validation time
			poeType.setTypeOfProof(TypeOfProof.VALIDATION);
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

		for (RevocationWrapper revocationData : diagnosticData.getAllRevocationData()) {
			addRevocationData(validationObjectListType, revocationData, poeExtraction);
		}

		for (TimestampWrapper timestamp : diagnosticData.getAllTimestamps()) {
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
			poeType.setTypeOfProof(TypeOfProof.PROVIDED);
		} else {
			poeType.setPOETime(currentTime);
			poeType.setTypeOfProof(TypeOfProof.VALIDATION);
			// TODO: check TypeOfProof correctness (when to use VALIDATION, when PROVIDED)
		}
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
		SignatureWrapper timestampedSignature = timestamp.getLastTimestampedSignature();
		if (timestampedSignature != null) {
			poeProvisioning.setSignatureReference(getSignatureReference(timestampedSignature));
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
		String sourceAddress = revocationData.getSourceAddress();
		if (Utils.isStringNotEmpty(sourceAddress)) {
			representation.setURI(sourceAddress);
		}
		validationObject.setValidationObject(representation);
		validationObject.setPOE(getPOE(revocationData.getId(), poeExtraction));
		validationObject.setValidationReport(getValidationReport(revocationData));
		validationObjectListType.getValidationObject().add(validationObject);
	}

	private ValidationStatusType getSignatureValidationStatus(SignatureWrapper signature) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();

		Indication indication = detailedReport.getHighestIndication(signature.getId());
		if (indication != null) {
			validationStatus.setMainIndication(MainIndication.valueOf(indication.name()));
			SubIndication subIndication = detailedReport.getHighestSubIndication(signature.getId());
			if (subIndication != null) {
				validationStatus.getSubIndication().add(eu.europa.esig.jaxb.validationreport.enums.SubIndication.valueOf(subIndication.name()));
			}
		}

		validationStatus.getAssociatedValidationReportData().add(getValidationReportData(signature));
		return validationStatus;
	}

	private ValidationStatusType getValidationStatus(AbstractTokenProxy token) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();
		validationStatus.getAssociatedValidationReportData().add(getValidationReportData(token));
		return validationStatus;
	}

	private ValidationReportDataType getValidationReportData(AbstractTokenProxy token) {
		ValidationReportDataType validationReportData = objectFactory.createValidationReportDataType();
		XmlBasicBuildingBlocks basicBuildingBlockSignature = detailedReport.getBasicBuildingBlockById(token.getId());
		if (basicBuildingBlockSignature != null) {
			XmlCertificateChain certificateChain = basicBuildingBlockSignature.getCertificateChain();
			if (certificateChain != null) {
				fillCertificateChainAndTrustAnchor(validationReportData, certificateChain);
			}
		}

		XmlSubXCV signingCertificate = detailedReport.getSigningCertificate(token.getId());
		if (signingCertificate != null && signingCertificate.getRevocationInfo() != null) {
			fillRevocationInfo(validationReportData, signingCertificate.getRevocationInfo());
		}

		XmlBasicBuildingBlocks basicBuildingBlockById = detailedReport.getBasicBuildingBlockById(token.getId());
		if (basicBuildingBlockById != null) {
			XmlSAV sav = basicBuildingBlockById.getSAV();
			if (sav != null && sav.getCryptographicInfo() != null) {
				fillCryptographicInfo(validationReportData, sav.getCryptographicInfo());
			}
		}

		return validationReportData;
	}

	private void fillCryptographicInfo(ValidationReportDataType validationReportData, XmlCryptographicInformation cryptographicInfo) {
		CryptoInformationType cryptoInformationType = objectFactory.createCryptoInformationType();
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
		sigId.setDocHashOnly(sigWrapper.isDocHashOnly());
		sigId.setHashOnly(sigWrapper.isHashOnly());
		sigId.setDigestAlgAndValue(getDTBSRDigestAlgAndValue(sigWrapper.getDigestMatchers()));
		SignatureValueType sigValue = new SignatureValueType();
		sigValue.setValue(sigWrapper.getSignatureValue());
		sigId.setSignatureValue(sigValue);
		// TODO: add DAIdentifier
		return sigId;
	}
	
	private DigestAlgAndValueType getDTBSRDigestAlgAndValue(List<XmlDigestMatcher> digestMatchers) {
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			if (digestMatchers.size() == 1) {
				XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
				return getDigestAlgAndValueType(xmlDigestMatcher.getDigestMethod(), xmlDigestMatcher.getDigestValue());
			}
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				if (DigestMatcherType.SIGNED_PROPERTIES.equals(digestMatcher.getType()) &&
						Utils.isStringNotEmpty(digestMatcher.getDigestMethod()) && Utils.isArrayNotEmpty(digestMatcher.getDigestValue())) {
					return getDigestAlgAndValueType(digestMatcher.getDigestMethod(), digestMatcher.getDigestValue());
				}
			}
		}
		return null;
	}
	
	private void getSignersDocuments(SignatureValidationReportType signatureValidationReport, SignatureWrapper sigWrapper) {
		// TODO: check for asics if to return a list of unzipped documents
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
		List<String> certIds = sigWrapper.getFoundCertificateIds(XmlCertificateLocationType.ATTR_AUTORITIES_CERT_VALUES);
		if (Utils.isCollectionNotEmpty(certIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttrAuthoritiesCertValues(buildTokenList(certIds)));
		}
	}

	private void addTimeStampValidationData(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> refIds = sigWrapper.getFoundCertificateIds(XmlCertificateLocationType.TIMESTAMP_DATA_VALIDATION);
		refIds.addAll(sigWrapper.getRevocationIdsByOrigin(XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES));
		if (Utils.isCollectionNotEmpty(refIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeTimeStampValidationData(buildTokenList(refIds)));
		}
	}

	private void addCertificateValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> certIds = sigWrapper.getFoundCertificateIds(XmlCertificateLocationType.CERTIFICATE_VALUES);
		if (Utils.isCollectionNotEmpty(certIds)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCertificateValues(buildTokenList(certIds)));
		}
	}

	private void addAttributeCertificateRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByLocation(XmlCertificateLocationType.ATTRIBUTE_CERTIFICATE_REFS);
		if (Utils.isCollectionNotEmpty(certs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeAttributeCertificateRefs(buildCertIDListType(certs)));
		}
	}

	private void addCompleteCertificateRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByLocation(XmlCertificateLocationType.COMPLETE_CERTIFICATE_REFS);
		if (Utils.isCollectionNotEmpty(certs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeCompleteCertificateRefs(buildCertIDListType(certs)));
		}
	}

	private void addSigningCertificate(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlFoundCertificate> certs = sigWrapper.getFoundCertificatesByLocation(XmlCertificateLocationType.SIGNING_CERTIFICATE);
		if (Utils.isCollectionNotEmpty(certs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeSigningCertificate(buildCertIDListType(certs)));
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
			certIdList.getAttributeObject().add(getVOReference(cert.getCertificate().getId()));
			List<XmlCertificateRef> certificateRefs = cert.getCertificateRef();
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
		List<XmlRevocationRef> revocationRefs = sigWrapper.getFoundRevocationRefsByLocation(RevocationRefLocation.COMPLETE_REVOCATION_REFS);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
				.add(objectFactory.createSignatureAttributesTypeCompleteRevocationRefs(buildRevIDListType(revocationRefs)));
		}
	}
	
	private void addAttributeRevocationRefs(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<XmlRevocationRef> revocationRefs = sigWrapper.getFoundRevocationRefsByLocation(RevocationRefLocation.ATTRIBUTE_REVOCATION_REFS);
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
		List<String> revocationRefs = sigWrapper.getRevocationIdsByOrigin(XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES);
		if (Utils.isCollectionNotEmpty(revocationRefs)) {
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeRevocationValues(buildTokenList(revocationRefs)));
		}
	}
	
	private void addAttributeRevocationValues(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> revocationRefs = sigWrapper.getRevocationIdsByOrigin(XmlRevocationOrigin.INTERNAL_ATTRIBUTE_REVOCATION_VALUES);
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
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat()
					.add(objectFactory.createSignatureAttributesTypeMessageDigest(messageDigestType));
		}
	}

	private void addTimestampsByType(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper, TimestampType timestampType) {
		List<TimestampWrapper> timestampListByType = sigWrapper.getTimestampListByType(timestampType);
		// remove document timestamps (they will be present in DocTimeStamp element)
		List<TimestampWrapper> docTimestamps = sigWrapper.getTimestampListByLocation(TimestampLocation.DOC_TIMESTAMP);
		timestampListByType.removeAll(docTimestamps);
		for (TimestampWrapper timestampWrapper : timestampListByType) {
			SATimestampType timestamp = getSATimestampType(timestampWrapper);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(wrap(timestampType, timestamp));
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
		List<String> certIds = sigWrapper.getFoundCertificateIds(XmlCertificateLocationType.DSS);
		List<String> crlIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, XmlRevocationOrigin.INTERNAL_DSS);
		List<String> ocspIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_DSS);
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
		List<String> certIds = sigWrapper.getFoundCertificateIds(XmlCertificateLocationType.VRI);
		List<String> crlIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, XmlRevocationOrigin.INTERNAL_VRI);
		List<String> ocspIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_VRI);

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
		SASigningTimeType saSigningTimeType = objectFactory.createSASigningTimeType();
		saSigningTimeType.setTime(sigWrapper.getDateTime());
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(objectFactory.createSignatureAttributesTypeSigningTime(saSigningTimeType));
	}

}
