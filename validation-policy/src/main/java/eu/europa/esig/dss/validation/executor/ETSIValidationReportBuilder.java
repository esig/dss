package eu.europa.esig.dss.validation.executor;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.xml.bind.JAXBElement;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateLocationType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.RevocationRefLocation;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.jaxb.validationreport.AttributeBaseType;
import eu.europa.esig.jaxb.validationreport.ObjectFactory;
import eu.europa.esig.jaxb.validationreport.SACRLIDType;
import eu.europa.esig.jaxb.validationreport.SACertIDListType;
import eu.europa.esig.jaxb.validationreport.SACertIDType;
import eu.europa.esig.jaxb.validationreport.SACommitmentTypeIndicationType;
import eu.europa.esig.jaxb.validationreport.SAContactInfoType;
import eu.europa.esig.jaxb.validationreport.SADSSType;
import eu.europa.esig.jaxb.validationreport.SADataObjectFormatType;
import eu.europa.esig.jaxb.validationreport.SAFilterType;
import eu.europa.esig.jaxb.validationreport.SAMessageDigestType;
import eu.europa.esig.jaxb.validationreport.SANameType;
import eu.europa.esig.jaxb.validationreport.SAOCSPIDType;
import eu.europa.esig.jaxb.validationreport.SAOneSignerRoleType;
import eu.europa.esig.jaxb.validationreport.SAReasonType;
import eu.europa.esig.jaxb.validationreport.SARevIDListType;
import eu.europa.esig.jaxb.validationreport.SASignatureProductionPlaceType;
import eu.europa.esig.jaxb.validationreport.SASignerRoleType;
import eu.europa.esig.jaxb.validationreport.SASigningTimeType;
import eu.europa.esig.jaxb.validationreport.SASubFilterType;
import eu.europa.esig.jaxb.validationreport.SATimestampType;
import eu.europa.esig.jaxb.validationreport.SAVRIType;
import eu.europa.esig.jaxb.validationreport.SignatureAttributesType;
import eu.europa.esig.jaxb.validationreport.SignatureIdentifierType;
import eu.europa.esig.jaxb.validationreport.SignatureValidationProcessType;
import eu.europa.esig.jaxb.validationreport.SignatureValidationReportType;
import eu.europa.esig.jaxb.validationreport.SignerInformationType;
import eu.europa.esig.jaxb.validationreport.VOReferenceType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectListType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectRepresentationType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationStatusType;
import eu.europa.esig.jaxb.validationreport.ValidationTimeInfoType;
import eu.europa.esig.jaxb.validationreport.enums.EndorsementType;
import eu.europa.esig.jaxb.validationreport.enums.MainIndication;
import eu.europa.esig.jaxb.validationreport.enums.ObjectType;
import eu.europa.esig.jaxb.validationreport.enums.SignatureValidationProcessID;
import eu.europa.esig.jaxb.xmldsig.DigestMethodType;

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

		for (SignatureWrapper sigWrapper : diagnosticData.getAllSignatures()) {
			SignatureValidationReportType signatureValidationReport = objectFactory.createSignatureValidationReportType();
			signatureValidationReport.setSignatureIdentifier(getSignatureIdentifier(sigWrapper));
			signatureValidationReport.setSignatureAttributes(getSignatureAttributes(sigWrapper));
			signatureValidationReport.setSignerInformation(getSignerInformation(sigWrapper));
			signatureValidationReport.setSignatureValidationProcess(getSignatureValidationProcess(sigWrapper));
			signatureValidationReport.setSignatureValidationStatus(getValidationStatus(sigWrapper));
			signatureValidationReport.setValidationTimeInfo(getValidationTimeInfo(sigWrapper));

			result.setSignatureValidationReport(signatureValidationReport);
		}

		result.setSignatureValidationObjects(getSignatureValidationObjects());

		return result;
	}

	private ValidationTimeInfoType getValidationTimeInfo(SignatureWrapper sigWrapper) {
		ValidationTimeInfoType validationTimeInfoType = objectFactory.createValidationTimeInfoType();
		validationTimeInfoType.setValidationTime(currentTime);
		// TODO
		// validationTimeInfoType.setBestSignatureTime(POE);
		return validationTimeInfoType;
	}

	private SignerInformationType getSignerInformation(SignatureWrapper sigWrapper) {
		CertificateWrapper signingCert = sigWrapper.getSigningCertificate();
		if (signingCert == null) {
			return null;
		}
		SignerInformationType signerInfo = objectFactory.createSignerInformationType();
		// TODO
//		signerInfo.setPseudonym(true);
		signerInfo.setSigner(signingCert.getReadableCertificateName());
		signerInfo.setSignerCertificate(getVOReference(signingCert.getId()));
		return signerInfo;
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

		for (CertificateWrapper certificate : diagnosticData.getUsedCertificates()) {
			addCertificate(validationObjectListType, certificate);
		}

		for (TimestampWrapper timestamp : diagnosticData.getAllTimestamps()) {
			addTimestamp(validationObjectListType, timestamp);
		}

		for (RevocationWrapper revocationData : diagnosticData.getAllRevocationData()) {
			addRevocationData(validationObjectListType, revocationData);
		}

		return validationObjectListType;
	}

	private void addCertificate(ValidationObjectListType validationObjectListType, CertificateWrapper certificate) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(certificate.getId());
		validationObject.setObjectType(ObjectType.CERTIFICATE);
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		representation.setBase64(certificate.getBinaries());
		validationObject.setValidationObject(representation);
		validationObjectListType.getValidationObject().add(validationObject);
	}

	private void addTimestamp(ValidationObjectListType validationObjectListType, TimestampWrapper timestamp) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(timestamp.getId());
		validationObject.setObjectType(ObjectType.TIMESTAMP);
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		representation.setBase64(timestamp.getBinaries());
		validationObject.setValidationObject(representation);
		validationObjectListType.getValidationObject().add(validationObject);
	}

	private void addRevocationData(ValidationObjectListType validationObjectListType, RevocationWrapper revocationData) {
		ValidationObjectType validationObject = objectFactory.createValidationObjectType();
		validationObject.setId(revocationData.getId());
		if (RevocationType.CRL.equals(revocationData.getRevocationType())) {
			validationObject.setObjectType(ObjectType.CRL);
		} else {
			validationObject.setObjectType(ObjectType.OCSP_RESPONSE);
		}
		ValidationObjectRepresentationType representation = objectFactory.createValidationObjectRepresentationType();
		representation.setBase64(revocationData.getBinaries());
		validationObject.setValidationObject(representation);
		validationObjectListType.getValidationObject().add(validationObject);
	}

	private ValidationStatusType getValidationStatus(SignatureWrapper sigWrapper) {
		ValidationStatusType validationStatus = objectFactory.createValidationStatusType();

		Indication indication = detailedReport.getHighestIndication(sigWrapper.getId());
		validationStatus.setMainIndication(MainIndication.valueOf(indication.name()));
		SubIndication subIndication = detailedReport.getHighestSubIndication(sigWrapper.getId());
		if (subIndication != null) {
			validationStatus.getSubIndication().add(eu.europa.esig.jaxb.validationreport.enums.SubIndication.valueOf(subIndication.name()));
		}

		// TODO
//		validationStatus.getAssociatedValidationReportData().add(e);
		return validationStatus;
	}

	private SignatureIdentifierType getSignatureIdentifier(SignatureWrapper sigWrapper) {
		SignatureIdentifierType sigId = objectFactory.createSignatureIdentifierType();
		sigId.setId(sigWrapper.getId());

		// TODO
		sigId.setDocHashOnly(false);
		sigId.setHashOnly(false);
//		SignatureValueType sigValue = new SignatureValueType();
//		sigValue.setValue(value);
//		sigId.setSignatureValue(sigValue );

		return sigId;
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
		addTimestamps(sigAttributes, sigWrapper, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
		// see TS 119 102-2 - V1.2.1 A.6.3 CAdES
		addTimestamps(sigAttributes, sigWrapper, TimestampType.CONTENT_TIMESTAMP);
		// &lt;element name="IndividualDataObjectsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestamps(sigAttributes, sigWrapper, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		// &lt;element name="SigPolicyIdentifier" type="{http://uri.etsi.org/19102/v1.2.1#}SASigPolicyIdentifierType"/&gt;
		// &lt;element name="SignatureProductionPlace" type="{http://uri.etsi.org/19102/v1.2.1#}SASignatureProductionPlaceType"/&gt;
		addProductionPlace(sigAttributes, sigWrapper);
		// &lt;element name="SignerRole" type="{http://uri.etsi.org/19102/v1.2.1#}SASignerRoleType"/&gt;
		addSignerRoles(sigAttributes, sigWrapper);
		// &lt;element name="CounterSignature" type="{http://uri.etsi.org/19102/v1.2.1#}SACounterSignatureType"/&gt;
		// &lt;element name="SignatureTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestamps(sigAttributes, sigWrapper, TimestampType.SIGNATURE_TIMESTAMP);
		// &lt;element name="CompleteCertificateRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		addCompleteCertificateRefs(sigAttributes, sigWrapper);
		// &lt;element name="CompleteRevocationRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SARevIDListType"/&gt;
		addCompleteRevocationRefs(sigAttributes, sigWrapper);
		// &lt;element name="AttributeCertificateRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		addAttributeCertificateRefs(sigAttributes, sigWrapper);
		// &lt;element name="AttributeRevocationRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SARevIDListType"/&gt;
		addAttributeRevocationRefs(sigAttributes, sigWrapper);
		// &lt;element name="SigAndRefsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestamps(sigAttributes, sigWrapper, TimestampType.VALIDATION_DATA_TIMESTAMP);
		// &lt;element name="RefsOnlyTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		addTimestamps(sigAttributes, sigWrapper, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
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
		addTimestamps(sigAttributes, sigWrapper, TimestampType.ARCHIVE_TIMESTAMP);
		// &lt;element name="RenewedDigests" type="{http://uri.etsi.org/19102/v1.2.1#}SAListOfIntegersType"/&gt;
		// &lt;element name="MessageDigest" type="{http://uri.etsi.org/19102/v1.2.1#}SAMessageDigestType"/&gt;
		addMessageDigest(sigAttributes, sigWrapper);
		// &lt;element name="DSS" type="{http://uri.etsi.org/19102/v1.2.1#}SADSSType"/&gt;
		addDSS(sigAttributes, sigWrapper);
		// &lt;element name="VRI" type="{http://uri.etsi.org/19102/v1.2.1#}SAVRIType"/&gt;
		addVRI(sigAttributes, sigWrapper);
		// &lt;element name="DocTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		// TODO: DocTimeStamp
		// &lt;element name="Reason" type="{http://uri.etsi.org/19102/v1.2.1#}SAReasonType"/&gt;
		addReason(sigAttributes, sigWrapper);
		// &lt;element name="Name" type="{http://uri.etsi.org/19102/v1.2.1#}SANameType"/&gt;
		addSignatureName(sigAttributes, sigWrapper);
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
					digestMethodType.setAlgorithm(DigestAlgorithm.valueOf(digestAlgoAndValue.getDigestMethod()).getXmlId());
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
				digestMethodType.setAlgorithm(DigestAlgorithm.valueOf(digestAlgoAndValue.getDigestMethod()).getXmlId());
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

	private CertificateWrapper getCertificateWrapper(String certId) {
		return diagnosticData.getUsedCertificateById(certId);
	}

	private void addMessageDigest(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		XmlDigestMatcher messageDigest = sigWrapper.getMessageDigest();
		if (messageDigest != null) {
			SAMessageDigestType messageDigestType = objectFactory.createSAMessageDigestType();
			messageDigestType.setDigest(messageDigest.getDigestValue());
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(messageDigestType);
		}
	}

	private void addTimestamps(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper, TimestampType timestampType) {
		List<TimestampWrapper> timestampListByType = sigWrapper.getTimestampListByType(timestampType);
		for (TimestampWrapper timestampWrapper : timestampListByType) {
			SATimestampType timestamp = objectFactory.createSATimestampType();
			timestamp.setTimeStampValue(timestampWrapper.getProductionTime());
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(wrap(timestampType, timestamp));
		}
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
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(dataObjectFormatType);
		}
	}

	private void addCommitmentTypeIndications(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<String> commitmentTypeIdentifiers = sigWrapper.getCommitmentTypeIdentifiers();
		if (Utils.isCollectionNotEmpty(commitmentTypeIdentifiers)) {
			for (String commitmentTypeIdentifier : commitmentTypeIdentifiers) {
				SACommitmentTypeIndicationType commitmentType = objectFactory.createSACommitmentTypeIndicationType();
				commitmentType.setCommitmentTypeIdentifier(commitmentTypeIdentifier);
				sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(commitmentType);
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
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(signerRoleType);
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

	private void addProductionPlace(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
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
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(sigProductionPlace);
		}
	}

	private void addFilter(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String filter = sigWrapper.getFilter();
		if (Utils.isStringNotEmpty(filter)) {
			SAFilterType filterType = objectFactory.createSAFilterType();
			filterType.setFilter(filter);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(filterType);
		}
	}

	private void addSubFilter(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String subFilter = sigWrapper.getSubFilter();
		if (Utils.isStringNotEmpty(subFilter)) {
			SASubFilterType subFilterType = objectFactory.createSASubFilterType();
			subFilterType.setSubFilterElement(subFilter);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(subFilterType);
		}
	}

	private void addContactInfo(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String contactInfo = sigWrapper.getContactInfo();
		if (Utils.isStringNotEmpty(contactInfo)) {
			SAContactInfoType contactInfoType = objectFactory.createSAContactInfoType();
			contactInfoType.setContactInfoElement(contactInfo);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(contactInfoType);
		}
	}

	private void addSignatureName(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String signatureName = sigWrapper.getSignatureName();
		if (Utils.isStringNotEmpty(signatureName)) {
			SANameType nameType = objectFactory.createSANameType();
			nameType.setNameElement(signatureName);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(nameType);
		}
	}

	private void addReason(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		String reason = sigWrapper.getReason();
		if (Utils.isStringNotEmpty(reason)) {
			SAReasonType reasonType = objectFactory.createSAReasonType();
			reasonType.setReasonElement(reason);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(reasonType);
		}
	}
	
	private void addSignatureByteRange(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		List<BigInteger> signatureByteRange = sigWrapper.getSignatureByteRange();
		if (Utils.isCollectionNotEmpty(signatureByteRange)) {
			JAXBElement<List<BigInteger>> byteRangeObject = objectFactory.createSignatureAttributesTypeByteRange(signatureByteRange);
			sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(byteRangeObject);
		}
	}

	private void addDSS(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		SADSSType dssType = objectFactory.createSADSSType();
		
		List<String> certIds = sigWrapper.getFoundCertificateIds(XmlCertificateLocationType.DSS);
		if (Utils.isCollectionNotEmpty(certIds)) {
			dssType.setCerts(getVOReference(certIds));
		}
		List<String> crlIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, XmlRevocationOrigin.INTERNAL_DSS);
		if (Utils.isCollectionNotEmpty(crlIds)) {
			dssType.setCRLs(getVOReference(crlIds));
		}
		List<String> ocspIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_DSS);
		if (Utils.isCollectionNotEmpty(ocspIds)) {
			dssType.setOCSPs(getVOReference(ocspIds));
		}
		
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(dssType);
	}

	private void addVRI(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {		
		SAVRIType vriType = objectFactory.createSAVRIType();
		
		List<String> certIds = sigWrapper.getFoundCertificateIds(XmlCertificateLocationType.VRI);
		if (Utils.isCollectionNotEmpty(certIds)) {
			vriType.setCerts(getVOReference(certIds));
		}
		List<String> crlIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, XmlRevocationOrigin.INTERNAL_VRI);
		if (Utils.isCollectionNotEmpty(crlIds)) {
			vriType.setCRLs(getVOReference(crlIds));
		}
		List<String> ocspIds = sigWrapper.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_VRI);
		if (Utils.isCollectionNotEmpty(ocspIds)) {
			vriType.setOCSPs(getVOReference(ocspIds));
		}
		
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(vriType);
	}


	private void addSigningTime(SignatureAttributesType sigAttributes, SignatureWrapper sigWrapper) {
		SASigningTimeType saSigningTimeType = objectFactory.createSASigningTimeType();
		saSigningTimeType.setTime(sigWrapper.getDateTime());
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(saSigningTimeType);
	}

}
