package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.validationreport.SACommitmentTypeIndicationType;
import eu.europa.esig.jaxb.validationreport.SAContactInfoType;
import eu.europa.esig.jaxb.validationreport.SAFilterType;
import eu.europa.esig.jaxb.validationreport.SANameType;
import eu.europa.esig.jaxb.validationreport.SAOneSignerRoleType;
import eu.europa.esig.jaxb.validationreport.SAReasonType;
import eu.europa.esig.jaxb.validationreport.SASignatureProductionPlaceType;
import eu.europa.esig.jaxb.validationreport.SASignerRoleType;
import eu.europa.esig.jaxb.validationreport.SASigningTimeType;
import eu.europa.esig.jaxb.validationreport.SASubFilterType;
import eu.europa.esig.jaxb.validationreport.SignatureAttributesType;
import eu.europa.esig.jaxb.validationreport.SignatureIdentifierType;
import eu.europa.esig.jaxb.validationreport.SignatureValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.enums.EndorsementType;

public class ETSIValidationReportBuilder {

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
		ValidationReportType result = new ValidationReportType();

		for (SignatureWrapper sigWrapper : diagnosticData.getAllSignatures()) {
			SignatureValidationReportType signatureValidationReport = new SignatureValidationReportType();
			signatureValidationReport.setSignatureIdentifier(getSignatureIdentifier(sigWrapper));
			signatureValidationReport.setSignatureAttributes(getSignatureAttributes(sigWrapper));

			result.setSignatureValidationReport(signatureValidationReport);
		}

		return result;
	}

	private SignatureIdentifierType getSignatureIdentifier(SignatureWrapper sigWrapper) {
		SignatureIdentifierType sigId = new SignatureIdentifierType();
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
		SignatureAttributesType sigAttributes = new SignatureAttributesType();
		// &lt;element name="SigningTime" type="{http://uri.etsi.org/19102/v1.2.1#}SASigningTimeType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(signingTime(sigWrapper));
		// &lt;element name="SigningCertificate" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		// &lt;element name="DataObjectFormat" type="{http://uri.etsi.org/19102/v1.2.1#}SADataObjectFormatType"/&gt;
		// &lt;element name="CommitmentTypeIndication" type="{http://uri.etsi.org/19102/v1.2.1#}SACommitmentTypeIndicationType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(commitmentTypeIndication(sigWrapper));
		// &lt;element name="AllDataObjectsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		// &lt;element name="IndividualDataObjectsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		// &lt;element name="SigPolicyIdentifier" type="{http://uri.etsi.org/19102/v1.2.1#}SASigPolicyIdentifierType"/&gt;
		// &lt;element name="SignatureProductionPlace" type="{http://uri.etsi.org/19102/v1.2.1#}SASignatureProductionPlaceType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(productionPlace(sigWrapper));
		// &lt;element name="SignerRole" type="{http://uri.etsi.org/19102/v1.2.1#}SASignerRoleType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(signerRole(sigWrapper));
		// &lt;element name="CounterSignature" type="{http://uri.etsi.org/19102/v1.2.1#}SACounterSignatureType"/&gt;
		// &lt;element name="SignatureTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		// &lt;element name="CompleteCertificateRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		// &lt;element name="CompleteRevocationRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SARevIDListType"/&gt;
		// &lt;element name="AttributeCertificateRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SACertIDListType"/&gt;
		// &lt;element name="AttributeRevocationRefs" type="{http://uri.etsi.org/19102/v1.2.1#}SARevIDListType"/&gt;
		// &lt;element name="SigAndRefsTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		// &lt;element name="RefsOnlyTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		// &lt;element name="CertificateValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		// &lt;element name="RevocationValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		// &lt;element name="AttrAuthoritiesCertValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		// &lt;element name="AttributeRevocationValues" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		// &lt;element name="TimeStampValidationData" type="{http://uri.etsi.org/19102/v1.2.1#}AttributeBaseType"/&gt;
		// &lt;element name="ArchiveTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		// &lt;element name="RenewedDigests" type="{http://uri.etsi.org/19102/v1.2.1#}SAListOfIntegersType"/&gt;
		// &lt;element name="MessageDigest" type="{http://uri.etsi.org/19102/v1.2.1#}SAMessageDigestType"/&gt;
		// &lt;element name="DSS" type="{http://uri.etsi.org/19102/v1.2.1#}SADSSType"/&gt;
		// &lt;element name="VRI" type="{http://uri.etsi.org/19102/v1.2.1#}SAVRIType"/&gt;
		// &lt;element name="DocTimeStamp" type="{http://uri.etsi.org/19102/v1.2.1#}SATimestampType"/&gt;
		// &lt;element name="Reason" type="{http://uri.etsi.org/19102/v1.2.1#}SAReasonType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(reason(sigWrapper));
		// &lt;element name="Name" type="{http://uri.etsi.org/19102/v1.2.1#}SANameType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(signatureName(sigWrapper));
		// &lt;element name="ContactInfo" type="{http://uri.etsi.org/19102/v1.2.1#}SAContactInfoType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(contactInfo(sigWrapper));
		// &lt;element name="SubFilter" type="{http://uri.etsi.org/19102/v1.2.1#}SASubFilterType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(subFilter(sigWrapper));
		// &lt;element name="ByteRange" type="{http://uri.etsi.org/19102/v1.2.1#}SAListOfIntegersType"/&gt;
//		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(byteRange(sigWrapper));
		// &lt;element name="Filter" type="{http://uri.etsi.org/19102/v1.2.1#}SAFilterType"/&gt;
		sigAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat().add(filter(sigWrapper));
		return sigAttributes;
	}

	private SACommitmentTypeIndicationType commitmentTypeIndication(SignatureWrapper sigWrapper) {
		List<String> commitmentTypeIdentifiers = sigWrapper.getCommitmentTypeIdentifiers();
		if (Utils.isCollectionEmpty(commitmentTypeIdentifiers)) {
			return null;
		}
		SACommitmentTypeIndicationType commitmentType = new SACommitmentTypeIndicationType();
		for (String commitmentTypeIdentifier : commitmentTypeIdentifiers) {
			// TODO missing multi-values
			commitmentType.setCommitmentTypeIdentifier(commitmentTypeIdentifier);
		}
		return commitmentType;
	}

	private SASignerRoleType signerRole(SignatureWrapper sigWrapper) {
		List<String> claimedRoles = sigWrapper.getClaimedRoles();
		List<String> certifiedRoles = sigWrapper.getCertifiedRoles();
		if (Utils.isCollectionEmpty(claimedRoles) && Utils.isCollectionEmpty(certifiedRoles)) {
			return null;
		}
		SASignerRoleType signerRoleType = new SASignerRoleType();
		addSignerRoles(signerRoleType, claimedRoles, EndorsementType.CLAIMED);
		addSignerRoles(signerRoleType, certifiedRoles, EndorsementType.CERTIFIED);
		return signerRoleType;
	}

	private void addSignerRoles(SASignerRoleType signerRoleType, List<String> roles, EndorsementType endorsement) {
		for (String role : roles) {
			SAOneSignerRoleType oneSignerRole = new SAOneSignerRoleType();
			oneSignerRole.setRole(role);
			oneSignerRole.setEndorsementType(endorsement);
			signerRoleType.getRoleDetails().add(oneSignerRole);
		}
	}

	private SASignatureProductionPlaceType productionPlace(SignatureWrapper sigWrapper) {
		final String address = sigWrapper.getAddress();
		final String city = sigWrapper.getCity();
		final String stateOrProvince = sigWrapper.getStateOrProvince();
		final String postalCode = sigWrapper.getPostalCode();
		final String countryName = sigWrapper.getCountryName();

		if (Utils.isAtLeastOneNotEmpty(address, city, stateOrProvince, postalCode, countryName)) {
			SASignatureProductionPlaceType sigProductionPlace = new SASignatureProductionPlaceType();
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
			return sigProductionPlace;
		}
		return null;
	}

	private SAFilterType filter(SignatureWrapper sigWrapper) {
		String filter = sigWrapper.getFilter();
		if (Utils.isStringEmpty(filter)) {
			return null;
		}
		SAFilterType filterType = new SAFilterType();
		filterType.setFilter(filter);
		return filterType;
	}

	private SASubFilterType subFilter(SignatureWrapper sigWrapper) {
		String subFilter = sigWrapper.getSubFilter();
		if (Utils.isStringEmpty(subFilter)) {
			return null;
		}
		SASubFilterType subFilterType = new SASubFilterType();
		subFilterType.setSubFilterElement(subFilter);
		return subFilterType;
	}

	private SAReasonType reason(SignatureWrapper sigWrapper) {
		String reason = sigWrapper.getReason();
		if (Utils.isStringEmpty(reason)) {
			return null;
		}
		SAReasonType reasonType = new SAReasonType();
		reasonType.setReasonElement(reason);
		return reasonType;
	}

//	private SAListOfIntegersType byteRange(SignatureWrapper sigWrapper) {
//		// TODO Auto-generated method stub
//		return null;
//	}

	private SAContactInfoType contactInfo(SignatureWrapper sigWrapper) {
		String contactInfo = sigWrapper.getContactInfo();
		if (Utils.isStringEmpty(contactInfo)) {
			return null;
		}
		SAContactInfoType contactInfoType = new SAContactInfoType();
		contactInfoType.setContactInfoElement(contactInfo);
		return contactInfoType;
	}

	private SANameType signatureName(SignatureWrapper sigWrapper) {
		String signatureName = sigWrapper.getSignatureName();
		if (Utils.isStringEmpty(signatureName)) {
			return null;
		}
		SANameType nameType = new SANameType();
		nameType.setNameElement(signatureName);
		return nameType;
	}

	private SASigningTimeType signingTime(SignatureWrapper sigWrapper) {
		SASigningTimeType signingTime = new SASigningTimeType();
		signingTime.setTime(sigWrapper.getDateTime());
		return signingTime;
	}

}
