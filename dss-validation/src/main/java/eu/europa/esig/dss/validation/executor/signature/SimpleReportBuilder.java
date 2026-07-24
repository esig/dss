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
package eu.europa.esig.dss.validation.executor.signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationPayloadProxy;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.claim.AddressClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.AgeOverNNClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.AttestedAttributesSubjectClaimIdWrapper;
import eu.europa.esig.dss.diagnostic.claim.BiometricTemplateXXClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DeviceKeyClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.PlaceOfBirthClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.StatusClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.ValidityInfoClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceProvider;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlDisclosableClaim;
import eu.europa.esig.dss.simplereport.jaxb.XmlEAALevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlEAAPayload;
import eu.europa.esig.dss.simplereport.jaxb.XmlEAA;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecords;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlPDFAInfo;
import eu.europa.esig.dss.simplereport.jaxb.XmlParametrizedDisclosableClaim;
import eu.europa.esig.dss.simplereport.jaxb.XmlSemantic;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestampLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.simplereport.jaxb.XmlTrustAnchor;
import eu.europa.esig.dss.simplereport.jaxb.XmlTrustAnchors;
import eu.europa.esig.dss.simplereport.jaxb.XmlValidationMessages;
import eu.europa.esig.dss.simplereport.jaxb.XmlValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data and detailed validation report.
 */
public class SimpleReportBuilder {

	/** i18nProvider */
	private final I18nProvider i18nProvider;

	/** Defines if the semantics shall be included */
	private final boolean includeSemantics;

	/** The validation time */
	private final Date currentTime;

	/** The validation policy */
	private final ValidationPolicy policy;

	/** The DiagnosticData to use */
	private final DiagnosticData diagnosticData;

	/** The detailed report */
	private final DetailedReport detailedReport;

	/** The number of processed signatures */
	private int totalSignatureCount = 0;

	/** The number of valid signatures */
	private int validSignatureCount = 0;

	/** Set of all used Indications (used for semantics) */
	private final Set<Indication> finalIndications = new HashSet<>();

	/** Set of all used SubIndications (used for semantics) */
	private final Set<SubIndication> finalSubIndications = new HashSet<>();

	/** The POE set */
	private POEExtraction poe;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentTime {@link Date} validation time
	 * @param policy {@link ValidationPolicy}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param detailedReport {@link DetailedReport}
	 * @param includeSemantics defines if the semantics shall be included
	 */
	public SimpleReportBuilder(I18nProvider i18nProvider, Date currentTime, ValidationPolicy policy,
			DiagnosticData diagnosticData, DetailedReport detailedReport, boolean includeSemantics) {
		this.currentTime = currentTime;
		this.policy = policy;
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.i18nProvider = i18nProvider;
		this.includeSemantics = includeSemantics;
	}

	/**
	 * This method generates the validation simpleReport.
	 *
	 * @return the object representing {@code XmlSimpleReport}
	 */
	public XmlSimpleReport build() {
		validSignatureCount = 0;
		totalSignatureCount = 0;

		poe = new POEExtraction();
		poe.init(diagnosticData, diagnosticData.getValidationDate());
		poe.collectAllPOE(diagnosticData.getTimestampList());

		final XmlSimpleReport simpleReport = new XmlSimpleReport();

		addPolicyNode(simpleReport);
		addValidationTime(simpleReport);
		addDocumentName(simpleReport);

		boolean containerInfoPresent = diagnosticData.isContainerInfoPresent();
		if (containerInfoPresent) {
			addContainerType(simpleReport);
		}

		Set<String> attachedSignatureIds = new HashSet<>();
		Set<String> attachedTimestampIds = new HashSet<>();
		Set<String> attachedEvidenceRecordIds = new HashSet<>();
		if (Utils.isCollectionNotEmpty(diagnosticData.getEAAs())) {
			for (AttestationWrapper eaa : diagnosticData.getEAAs()) {
				attachedSignatureIds.addAll(eaa.getEAASignatureIds());
				if (eaa.getKeyBindingSignature() != null) {
					attachedSignatureIds.add(eaa.getKeyBindingSignatureId());
				}
				simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(getEAA(eaa));
			}
		}

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			if (attachedSignatureIds.contains(signature.getId())) {
				continue;
			}
			attachedTimestampIds.addAll(signature.getTimestampIdsList());
			attachedEvidenceRecordIds.addAll(signature.getEvidenceRecordIdsList());
			attachedTimestampIds.addAll(signature.getEvidenceRecordTimestampIds());
			simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(getSignature(signature, containerInfoPresent));
		}

		for (TimestampWrapper timestamp : diagnosticData.getNonEvidenceRecordTimestamps()) {
			if (attachedTimestampIds.contains(timestamp.getId())) {
				continue;
			}
			attachedTimestampIds.add(timestamp.getId());
			attachedEvidenceRecordIds.addAll(timestamp.getEvidenceRecordIdsList());
			attachedTimestampIds.addAll(timestamp.getEvidenceRecordTimestampIds());
			Indication tstValidationIndication = detailedReport.getBasicTimestampValidationIndication(timestamp.getId());
			if (tstValidationIndication != null) {
				XmlTimestamp xmlTimestamp = getXmlTimestamp(timestamp);
				if (isValidConclusion(timestamp.getId())) {
					// perform extension period check only for detached timestamps
					determineExtensionPeriod(xmlTimestamp);
				}
				simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(xmlTimestamp);
			}
		}

		for (EvidenceRecordWrapper evidenceRecord : diagnosticData.getEvidenceRecords()) {
			if (attachedEvidenceRecordIds.contains(evidenceRecord.getId())) {
				continue;
			}
			attachedTimestampIds.addAll(evidenceRecord.getTimestampIdsList());
			Indication erValidationIndication = detailedReport.getEvidenceRecordValidationIndication(evidenceRecord.getId());
			if (erValidationIndication != null) {
				simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(getXmlEvidenceRecord(evidenceRecord));
			}
		}

		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (attachedTimestampIds.contains(timestamp.getId())) {
				continue;
			}
			Indication tstValidationIndication = detailedReport.getBasicTimestampValidationIndication(timestamp.getId());
			if (tstValidationIndication != null) {
				simpleReport.getSignatureOrTimestampOrEvidenceRecord().add(getXmlTimestamp(timestamp));
			}
		}

		addStatistics(simpleReport);

		if (includeSemantics) {
			addSemantics(simpleReport);
		}

		addPDFAProfile(simpleReport);

		return simpleReport;
	}

	private void addPolicyNode(XmlSimpleReport report) {
		XmlValidationPolicy xmlPolicy = new XmlValidationPolicy();
		xmlPolicy.setPolicyName(policy.getPolicyName());
		xmlPolicy.setPolicyDescription(policy.getPolicyDescription());
		report.setValidationPolicy(xmlPolicy);
	}

	private void addValidationTime(XmlSimpleReport report) {
		report.setValidationTime(currentTime);
	}

	private void addDocumentName(XmlSimpleReport report) {
		report.setDocumentName(diagnosticData.getDocumentName());
	}

	private void addContainerType(XmlSimpleReport simpleReport) {
		simpleReport.setContainerType(diagnosticData.getContainerType());
	}

	private void addSemantics(XmlSimpleReport simpleReport) {

		for (Indication indication : finalIndications) {
			XmlSemantic semantic = new XmlSemantic();
			semantic.setKey(indication.name());
			semantic.setValue(i18nProvider.getMessage(MessageTag.getSemantic(indication.name())));
			simpleReport.getSemantic().add(semantic);
		}

		for (SubIndication subIndication : finalSubIndications) {
			XmlSemantic semantic = new XmlSemantic();
			semantic.setKey(subIndication.name());
			semantic.setValue(i18nProvider.getMessage(MessageTag.getSemantic(subIndication.name())));
			simpleReport.getSemantic().add(semantic);
		}

	}

	private void addStatistics(XmlSimpleReport simpleReport) {
		simpleReport.setValidSignaturesCount(validSignatureCount);
		simpleReport.setSignaturesCount(totalSignatureCount);
	}

	private void addPDFAProfile(XmlSimpleReport simpleReport) {
		String pdfaProfileId = diagnosticData.getPDFAProfileId();
		if (pdfaProfileId != null) {
			XmlPDFAInfo xmlPDFAInfo = new XmlPDFAInfo();
			xmlPDFAInfo.setPDFAProfile(pdfaProfileId);
			xmlPDFAInfo.setValid(diagnosticData.isPDFACompliant());
			if (Utils.isCollectionNotEmpty(diagnosticData.getPDFAValidationErrors())) {
				xmlPDFAInfo.setValidationMessages(toXmlValidationMessages(diagnosticData.getPDFAValidationErrors()));
			}
			simpleReport.setPDFAInfo(xmlPDFAInfo);
		}
	}

	private XmlValidationMessages toXmlValidationMessages(Collection<String> errors) {
		XmlValidationMessages xmlValidationMessages = new XmlValidationMessages();
		xmlValidationMessages.getError().addAll(errors);
		return xmlValidationMessages;
	}

	/**
	 * Builds a XmlSignature object
	 * 
	 * @param signature
	 *                  the signature wrapper
	 * @param container
	 *                  true if the current file is a container
	 */
	private XmlSignature getSignature(SignatureWrapper signature, boolean container) {

		totalSignatureCount++;

		String signatureId = signature.getId();
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setId(signatureId);

		addCounterSignature(signature, xmlSignature);
		addSignatureScope(signature, xmlSignature);
		addSigningTime(signature, xmlSignature);
		addBestSignatureTime(signature, xmlSignature);
		addSignatureFormat(signature, xmlSignature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		if (signingCertificate != null) {
			xmlSignature.setSignedBy(getReadableCertificateName(signingCertificate.getId()));
		}

		XmlDetails validationDetails = getAdESValidationDetails(signatureId);
		if (isNotEmpty(validationDetails)) {
			xmlSignature.setAdESValidationDetails(validationDetails);
		}

		XmlDetails qualificationDetails = getQualificationDetails(signatureId);
		if (isNotEmpty(qualificationDetails)) {
			xmlSignature.setQualificationDetails(qualificationDetails);
		}

		if (container) {
			xmlSignature.setFilename(signature.getFilename());
		}

		Indication indication = detailedReport.getFinalIndication(signatureId);
		SubIndication subIndication = detailedReport.getFinalSubIndication(signatureId);
		if (Indication.TOTAL_PASSED.equals(indication)) {
			determineExtensionPeriod(xmlSignature);
			++validSignatureCount;

		} else if (Indication.INDETERMINATE.equals(indication) && SubIndication.TRY_LATER.equals(subIndication)) {
			// indication is temporary, execute when applicable
			determineExtensionPeriod(xmlSignature);
		}

		xmlSignature.setIndication(indication);
		finalIndications.add(indication);

		if (subIndication != null) {
			xmlSignature.setSubIndication(subIndication);
			finalSubIndications.add(subIndication);
		}

		addSignatureProfile(xmlSignature);

		xmlSignature.setCertificateChain(getCertChain(signatureId));

		List<EvidenceRecordWrapper> evidenceRecordList = signature.getEvidenceRecords();
		if (Utils.isCollectionNotEmpty(evidenceRecordList)) {
			XmlEvidenceRecords xmlEvidenceRecords = new XmlEvidenceRecords();
			for (EvidenceRecordWrapper evidenceRecord : evidenceRecordList) {
				Indication erIndication = detailedReport.getEvidenceRecordValidationIndication(evidenceRecord.getId());
				if (erIndication != null) {
					xmlEvidenceRecords.getEvidenceRecord().add(getXmlEvidenceRecord(evidenceRecord));
				}
			}
			if (Utils.isCollectionNotEmpty(xmlEvidenceRecords.getEvidenceRecord())) {
				xmlSignature.setEvidenceRecords(xmlEvidenceRecords);
			}
		}

		List<TimestampWrapper> timestampList = signature.getTimestampList();
		if (Utils.isCollectionNotEmpty(timestampList)) {
			XmlTimestamps xmlTimestamps = new XmlTimestamps();
			for (TimestampWrapper timestamp : timestampList) {
				Indication tstValidationIndication = detailedReport.getBasicTimestampValidationIndication(timestamp.getId());
				if (tstValidationIndication != null) {
					xmlTimestamps.getTimestamp().add(getXmlTimestamp(timestamp));
				}
			}
			if (Utils.isCollectionNotEmpty(xmlTimestamps.getTimestamp())) {
				xmlSignature.setTimestamps(xmlTimestamps);
			}
		}

		return xmlSignature;
	}

	private XmlDetails getAdESValidationDetails(String tokenId) {
		XmlDetails validationDetails = new XmlDetails();
		validationDetails.getError().addAll(convert(detailedReport.getAdESValidationErrors(tokenId)));
		validationDetails.getWarning().addAll(convert(detailedReport.getAdESValidationWarnings(tokenId)));
		validationDetails.getInfo().addAll(convert(detailedReport.getAdESValidationInfos(tokenId)));
		return validationDetails;
	}

	private XmlDetails getQualificationDetails(String tokenId) {
		XmlDetails qualificationDetails = new XmlDetails();
		qualificationDetails.getError().addAll(convert(detailedReport.getQualificationErrors(tokenId)));
		qualificationDetails.getWarning().addAll(convert(detailedReport.getQualificationWarnings(tokenId)));
		qualificationDetails.getInfo().addAll(convert(detailedReport.getQualificationInfos(tokenId)));
		return qualificationDetails;
	}

	private boolean isNotEmpty(XmlDetails details) {
		return Utils.isCollectionNotEmpty(details.getError()) || Utils.isCollectionNotEmpty(details.getWarning()) ||
				Utils.isCollectionNotEmpty(details.getInfo());
	}

	private List<XmlMessage> convert(Collection<Message> messages) {
		return messages.stream().map(m -> {
				XmlMessage xmlMessage = new XmlMessage();
				xmlMessage.setKey(m.getKey());
				xmlMessage.setValue(m.getValue());
				return xmlMessage;
			}).collect(Collectors.toList());
	}

	private XmlCertificateChain getCertChain(String tokenId) {
		List<String> certIds = detailedReport.getBasicBuildingBlocksCertChain(tokenId);
		XmlCertificateChain xmlCertificateChain = new XmlCertificateChain();
		if (Utils.isCollectionNotEmpty(certIds)) {
			for (String certId : certIds) {
				XmlCertificate certificate = new XmlCertificate();
				certificate.setId(certId);
				certificate.setQualifiedName(getReadableCertificateName(certId));
				if (isTrustAnchor(certId)) {
					certificate.setTrusted(true);
					certificate.setSunsetDate(getCertificateSunsetDate(certId));
					certificate.setTrustAnchors(getXmlTrustAnchors(certId));
				}
				xmlCertificateChain.getCertificate().add(certificate);
			}
		}
		return xmlCertificateChain;
	}

	private Date getCertificateSunsetDate(String certId) {
		CertificateWrapper certificate = diagnosticData.getCertificateById(certId);
		if (certificate != null) {
			return certificate.getTrustSunsetDate();
		}
		return null;
	}

	private XmlTrustAnchors getXmlTrustAnchors(String certId) {
		List<XmlTrustServiceProvider> xmlTrustServiceProviders = filterByCertificateId(certId);
		if (Utils.isCollectionNotEmpty(xmlTrustServiceProviders)) {
			final XmlTrustAnchors xmlTrustAnchors = new XmlTrustAnchors();
			for (XmlTrustServiceProvider trustServiceProvider : xmlTrustServiceProviders) {
				final XmlTrustAnchor trustAnchor = new XmlTrustAnchor();
				if (trustServiceProvider.getTL() != null) {
					trustAnchor.setCountryCode(trustServiceProvider.getTL().getCountryCode());
					trustAnchor.setTSLType(trustServiceProvider.getTL().getType());
				}
				trustAnchor.setTrustServiceProvider(getEnOrFirst(trustServiceProvider.getTSPNames()));
				List<String> tspRegistrationIdentifiers = trustServiceProvider.getTSPRegistrationIdentifiers();
				if (Utils.isCollectionNotEmpty(tspRegistrationIdentifiers)) {
					trustAnchor.setTrustServiceProviderRegistrationId(tspRegistrationIdentifiers.get(0));
				}
				trustAnchor.getTrustServiceName().addAll(getUniqueServiceNames(trustServiceProvider));
				xmlTrustAnchors.getTrustAnchor().add(trustAnchor);
			}
			return xmlTrustAnchors;
		}
		return null;
	}

	private Set<String> getUniqueServiceNames(XmlTrustServiceProvider trustServiceProvider) {
		Set<String> result = new HashSet<>();
		for (XmlTrustService xmlTrustService : trustServiceProvider.getTrustServices()) {
			result.add(getEnOrFirst(xmlTrustService.getServiceNames()));
		}
		return result;
	}

	private String getEnOrFirst(List<XmlLangAndValue> langAndValues) {
		if (Utils.isCollectionNotEmpty(langAndValues)) {
			for (XmlLangAndValue langAndValue : langAndValues) {
				if (langAndValue.getLang() != null && "en".equalsIgnoreCase(langAndValue.getLang())) {
					return langAndValue.getValue();
				}
			}
			return langAndValues.get(0).getValue();
		}
		return null;
	}

	private List<XmlTrustServiceProvider> filterByCertificateId(String certId) {
		CertificateWrapper certificate = diagnosticData.getCertificateById(certId);
		List<XmlTrustServiceProvider> result = new ArrayList<>();
		for (XmlTrustServiceProvider xmlTrustServiceProvider : certificate.getTrustServiceProviders()) {
			List<XmlTrustService> trustServices = xmlTrustServiceProvider.getTrustServices();
			boolean foundCertId = false;
			for (XmlTrustService xmlTrustService : trustServices) {
				if (Utils.areStringsEqual(certId, xmlTrustService.getServiceDigitalIdentifier().getId())) {
					foundCertId = true;
					break;
				}
			}
			if (foundCertId) {
				result.add(xmlTrustServiceProvider);
			}
		}
		return result;
	}

	private void addBestSignatureTime(SignatureWrapper signature, XmlSignature xmlSignature) {
		xmlSignature.setBestSignatureTime(detailedReport.getBestSignatureTime(signature.getId()));
	}

	private void addCounterSignature(SignatureWrapper signature, XmlSignature xmlSignature) {
		if (signature.isCounterSignature()) {
			xmlSignature.setCounterSignature(true);
			xmlSignature.setParentId(signature.getParent().getId());
		}
	}

	private void addSignatureScope(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		if (Utils.isCollectionNotEmpty(signatureScopes)) {
			for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope signatureScope : signatureScopes) {
				xmlSignature.getSignatureScope().add(getXmlSignatureScope(signatureScope));
			}
		}
	}

	private XmlSignatureScope getXmlSignatureScope(eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope signatureScope) {
		XmlSignatureScope xmlSignatureScope = new XmlSignatureScope();
		xmlSignatureScope.setId(signatureScope.getSignerData().getId());
		xmlSignatureScope.setName(signatureScope.getName());
		xmlSignatureScope.setScope(signatureScope.getScope());
		xmlSignatureScope.setValue(signatureScope.getDescription());
		return xmlSignatureScope;
	}

	private void addSigningTime(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		xmlSignature.setSigningTime(signature.getClaimedSigningTime());
	}

	private void addSignatureFormat(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		xmlSignature.setSignatureFormat(signature.getSignatureFormat());
	}

	private String getReadableCertificateName(final String certId) {
		CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateByIdNullSafe(certId);
		return certificateWrapper.getReadableCertificateName();
	}

	private boolean isTrustAnchor(final String certId) {
		CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateByIdNullSafe(certId);
		return certificateWrapper.isTrusted();
	}

	private void addSignatureProfile(final XmlSignature xmlSignature) {
		SignatureQualification qualification = detailedReport.getSignatureQualification(xmlSignature.getId());
		if (qualification != null) {
			XmlSignatureLevel sigLevel = new XmlSignatureLevel();
			sigLevel.setValue(qualification);
			sigLevel.setDescription(qualification.getLabel());
			xmlSignature.setSignatureLevel(sigLevel);
		}
	}

	private XmlTimestamp getXmlTimestamp(TimestampWrapper timestampWrapper) {
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		String timestampId = timestampWrapper.getId();
		xmlTimestamp.setId(timestampId);
		xmlTimestamp.setProductionTime(timestampWrapper.getProductionTime());
		xmlTimestamp.setProducedBy(getProducedByName(timestampWrapper));
		xmlTimestamp.setCertificateChain(getCertChain(timestampId));
		xmlTimestamp.setFilename(timestampWrapper.getFilename());

		Indication indication = detailedReport.getFinalIndication(timestampId);
		xmlTimestamp.setIndication(indication);
		finalIndications.add(indication);

		SubIndication subIndication = detailedReport.getFinalSubIndication(timestampId);
		if (subIndication != null) {
			xmlTimestamp.setSubIndication(subIndication);
			finalSubIndications.add(subIndication);
		}

		TimestampQualification timestampQualification = detailedReport.getTimestampQualification(timestampId);
		if (timestampQualification != null) {
			XmlTimestampLevel xmlTimestampLevel = new XmlTimestampLevel();
			xmlTimestampLevel.setValue(timestampQualification);
			xmlTimestampLevel.setDescription(timestampQualification.getLabel());
			xmlTimestamp.setTimestampLevel(xmlTimestampLevel);
		}

		XmlDetails validationDetails = getAdESValidationDetails(timestampId);
		if (isNotEmpty(validationDetails)) {
			xmlTimestamp.setAdESValidationDetails(validationDetails);
		}

		XmlDetails qualificationDetails = getQualificationDetails(timestampId);
		if (isNotEmpty(qualificationDetails)) {
			xmlTimestamp.setQualificationDetails(qualificationDetails);
		}

		if (Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes())) {
			for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope timestampScope : timestampWrapper.getTimestampScopes()) {
				xmlTimestamp.getTimestampScope().add(getXmlSignatureScope(timestampScope));
			}
		}

		if (Utils.isCollectionNotEmpty(timestampWrapper.getEvidenceRecords())) {
			XmlEvidenceRecords xmlEvidenceRecords = new XmlEvidenceRecords();
			for (EvidenceRecordWrapper evidenceRecord : timestampWrapper.getEvidenceRecords()) {
				Indication erIndication = detailedReport.getEvidenceRecordValidationIndication(evidenceRecord.getId());
				if (erIndication != null) {
					xmlEvidenceRecords.getEvidenceRecord().add(getXmlEvidenceRecord(evidenceRecord));
				}
			}
			if (Utils.isCollectionNotEmpty(xmlEvidenceRecords.getEvidenceRecord())) {
				xmlTimestamp.setEvidenceRecords(xmlEvidenceRecords);
			}
		}

		return xmlTimestamp;
	}

	private XmlEvidenceRecord getXmlEvidenceRecord(EvidenceRecordWrapper evidenceRecordWrapper) {
		XmlEvidenceRecord xmlEvidenceRecord = new XmlEvidenceRecord();

		String evidenceRecordId = evidenceRecordWrapper.getId();
		xmlEvidenceRecord.setId(evidenceRecordId);
		xmlEvidenceRecord.setFilename(evidenceRecordWrapper.getFilename());

		xmlEvidenceRecord.setPOETime(detailedReport.getEvidenceRecordLowestPOETime(evidenceRecordId));

		Indication indication = detailedReport.getFinalIndication(evidenceRecordId);
		xmlEvidenceRecord.setIndication(indication);
		finalIndications.add(indication);

		SubIndication subIndication = detailedReport.getFinalSubIndication(evidenceRecordId);
		if (subIndication != null) {
			xmlEvidenceRecord.setSubIndication(subIndication);
			finalSubIndications.add(subIndication);
		}

		XmlDetails validationDetails = getAdESValidationDetails(evidenceRecordId);
		if (isNotEmpty(validationDetails)) {
			xmlEvidenceRecord.setAdESValidationDetails(validationDetails);
		}

		if (isValidConclusion(evidenceRecordId)) {
			determineExtensionPeriod(xmlEvidenceRecord);
		}

		if (Utils.isCollectionNotEmpty(evidenceRecordWrapper.getEvidenceRecordScopes())) {
			for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope timestampScope : evidenceRecordWrapper.getEvidenceRecordScopes()) {
				xmlEvidenceRecord.getEvidenceRecordScope().add(getXmlSignatureScope(timestampScope));
			}
		}

		List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
		if (Utils.isCollectionNotEmpty(timestampList)) {
			XmlTimestamps xmlTimestamps = new XmlTimestamps();
			for (TimestampWrapper timestamp : timestampList) {
				Indication tstValidationIndication = detailedReport.getBasicTimestampValidationIndication(timestamp.getId());
				if (tstValidationIndication != null) {
					xmlTimestamps.getTimestamp().add(getXmlTimestamp(timestamp));
				}
			}
			if (Utils.isCollectionNotEmpty(xmlTimestamps.getTimestamp())) {
				xmlEvidenceRecord.setTimestamps(xmlTimestamps);
			}
		}

		if (evidenceRecordWrapper.isEmbedded()) {
			xmlEvidenceRecord.setEmbedded(true);
			xmlEvidenceRecord.setParentId(evidenceRecordWrapper.getParent().getId());
		}

		return xmlEvidenceRecord;
	}

	private String getProducedByName(TimestampWrapper timestampWrapper) {
		CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.getReadableCertificateName();
		}
		return Utils.EMPTY_STRING;
	}

	private void determineExtensionPeriod(XmlSignature xmlSignature) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(xmlSignature.getId());
		List<TimestampWrapper> timestampList = getAllTimestampsForSignature(signatureWrapper);
		xmlSignature.setExtensionPeriodMin(getMinExtensionPeriod(signatureWrapper, timestampList));
		xmlSignature.setExtensionPeriodMax(getMaxExtensionPeriod(signatureWrapper, timestampList));
	}

	private List<TimestampWrapper> getAllTimestampsForSignature(SignatureWrapper signatureWrapper) {
		final List<TimestampWrapper> timestampList = new ArrayList<>(signatureWrapper.getAllTimestampsProducedAfterSignatureCreation());
		timestampList.addAll(getEvidenceRecordTimestampsForTokenWithId(signatureWrapper.getId()));
		return timestampList;
	}

	private void determineExtensionPeriod(XmlTimestamp xmlTimestamp) {
		TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(xmlTimestamp.getId());
		List<TimestampWrapper> timestampList = getAllTimestampsForTimestamp(timestampWrapper);
		xmlTimestamp.setExtensionPeriodMin(getMinExtensionPeriod(timestampWrapper, timestampList));
		xmlTimestamp.setExtensionPeriodMax(getMaxExtensionPeriod(timestampWrapper, timestampList));
	}

	private List<TimestampWrapper> getAllTimestampsForTimestamp(TimestampWrapper timestampWrapper) {
		final List<TimestampWrapper> timestampList = new ArrayList<>();

		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			if (containObjectWithId(timestampedObjects, timestampWrapper.getId())) {
				timestampList.add(timestamp);
			}
		}

		timestampList.addAll(getEvidenceRecordTimestampsForTokenWithId(timestampWrapper.getId()));

		return timestampList;
	}

	private void determineExtensionPeriod(XmlEvidenceRecord xmlEvidenceRecord) {
		EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecordById(xmlEvidenceRecord.getId());
		List<TimestampWrapper> timestampList = getAllTimestampsForEvidenceRecord(evidenceRecordWrapper);
		xmlEvidenceRecord.setExtensionPeriodMin(getMinExtensionPeriodForTimestampList(timestampList));
		xmlEvidenceRecord.setExtensionPeriodMax(getMaxExtensionPeriodForTimestampList(timestampList));
	}

	private List<TimestampWrapper> getAllTimestampsForEvidenceRecord(EvidenceRecordWrapper evidenceRecordWrapper) {
		final List<TimestampWrapper> timestampList = new ArrayList<>(evidenceRecordWrapper.getTimestampList());
		timestampList.addAll(getEvidenceRecordTimestampsForTokenWithId(evidenceRecordWrapper.getId()));
		return timestampList;
	}

	private List<TimestampWrapper> getEvidenceRecordTimestampsForTokenWithId(String tokenId) {
		final List<TimestampWrapper> timestampList = new ArrayList<>();

		for (EvidenceRecordWrapper evidenceRecord : diagnosticData.getEvidenceRecords()) {
			if (!isValidConclusion(evidenceRecord.getId())) {
				continue;
			}

			List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
			if (containObjectWithId(coveredObjects, tokenId)) {
				timestampList.addAll(evidenceRecord.getTimestampList());
			}
		}

		return timestampList;
	}

	private XmlEAA getEAA(AttestationWrapper attestationWrapper) {
		XmlEAA xmlEAA = new XmlEAA();

		String eaaId = attestationWrapper.getId();
		xmlEAA.setId(eaaId);
		xmlEAA.setFilename(attestationWrapper.getFilename());

		Indication indication = detailedReport.getFinalIndication(eaaId);
		xmlEAA.setIndication(indication);
		finalIndications.add(indication);

		SubIndication subIndication = detailedReport.getFinalSubIndication(eaaId);
		if (subIndication != null) {
			xmlEAA.setSubIndication(subIndication);
			finalSubIndications.add(subIndication);
		}

		List<AttestationQualification> attestationQualifications = detailedReport.getEAAQualifications(eaaId);
		if (Utils.isCollectionNotEmpty(attestationQualifications)) {
			xmlEAA.getEAALevel().addAll(getXmlEAALevels(attestationQualifications));
		}

		XmlDetails validationDetails = getAdESValidationDetails(eaaId);
		if (isNotEmpty(validationDetails)) {
			xmlEAA.setAdESValidationDetails(validationDetails);
		}

		XmlDetails qualificationDetails = getQualificationDetails(eaaId);
		if (isNotEmpty(qualificationDetails)) {
			xmlEAA.setQualificationDetails(qualificationDetails);
		}

		List<SignatureWrapper> signatures = attestationWrapper.getEAASignatures();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (SignatureWrapper signature : signatures) {
				xmlEAA.getEAASignature().add(getSignature(signature, false));
			}
		}
		SignatureWrapper keyBindingSignature = attestationWrapper.getKeyBindingSignature();
		if (keyBindingSignature != null) {
			xmlEAA.setKeyBindingSignature(getSignature(keyBindingSignature, false));
		}

		xmlEAA.setEAAPayload(buildXmlEAAPayload(attestationWrapper));

		return xmlEAA;
	}

	private List<XmlEAALevel> getXmlEAALevels(List<AttestationQualification> attestationQualifications) {
		if (Utils.isCollectionEmpty(attestationQualifications)) {
			return Collections.emptyList();
		}
		final List<XmlEAALevel> result = new ArrayList<>();
		for (AttestationQualification attestationQualification : attestationQualifications) {
			XmlEAALevel xmlEAALevel = new XmlEAALevel();
			xmlEAALevel.setValue(attestationQualification);
			xmlEAALevel.setDescription(attestationQualification.getLabel());
			result.add(xmlEAALevel);
		}
		return result;
	}

	private Date getMinExtensionPeriod(AbstractTokenProxy token, List<TimestampWrapper> timestampList) {
		Date min = null;

		final List<List<CertificateWrapper>> chains = new ArrayList<>();
		chains.add(token.getCertificateChain());
		List<RelatedRevocationWrapper> relatedRevocations = getRelatedRevocations(token);
		for (RevocationWrapper revocation : relatedRevocations) {
			chains.add(revocation.getCertificateChain());
		}

		for (List<CertificateWrapper> certificateChain : chains) {
			Date certChainMin = getMinExtensionPeriodForChain(certificateChain, null);
			if (certChainMin != null) {
				if (min == null || min.before(certChainMin)) {
					min = certChainMin;
				}
			}
		}

		Date minExtensionPeriodForTimestampList = getMinExtensionPeriodForTimestampList(timestampList);
		if (minExtensionPeriodForTimestampList != null && (min == null || min.before(minExtensionPeriodForTimestampList))) {
			min = minExtensionPeriodForTimestampList;
		}

		return min;
	}

	private List<RelatedRevocationWrapper> getRelatedRevocations(AbstractTokenProxy token) {
		// Returns a list of revocation data protected by a timestamp.
		// Other revocation data do not need to be processed.
		return token.foundRevocations().getRelatedRevocationData().stream()
				.filter(r -> poe.getLowestPOE(r.getId()).isTokenProvided()).collect(Collectors.toList());
	}

	private Date getMinExtensionPeriodForTimestampList(List<TimestampWrapper> timestampList) {
		Date min = null;

		for (TimestampWrapper timestampWrapper : timestampList) {
			Date certChainMin = getMinExtensionPeriodForChain(timestampWrapper.getCertificateChain(), timestampWrapper.getProductionTime());
			if (certChainMin != null) {
				if (min == null || min.before(certChainMin)) {
					min = certChainMin;
				}
			}
		}

		return min;
	}

	private Date getMinExtensionPeriodForChain(List<CertificateWrapper> certificateChain, Date usageTime) {
		Date min = null;
		for (CertificateWrapper certificateWrapper : certificateChain) {
			if (certificateWrapper.isTrusted() || certificateWrapper.isSelfSigned()) {
				break;
			}

			if (Utils.isCollectionNotEmpty(certificateWrapper.getCertificateRevocationData())) {
				Date lastTrustedUsage;
				if (usageTime != null) {
					lastTrustedUsage = usageTime;
				} else {
					lastTrustedUsage = poe.getLowestPOETime(certificateWrapper.getId());
				}

				Date tempMin = null;
				boolean goodRevocationFound = false;

				List<CertificateRevocationWrapper> certificateRevocationData = certificateWrapper.getCertificateRevocationData();
				for (CertificateRevocationWrapper revocationData : certificateRevocationData) {
					// Revocation data shall be issued after the POE time
					if (lastTrustedUsage.before(revocationData.getThisUpdate())) {
						goodRevocationFound = true;
						break;

					} else {
						Date nextUpdate = revocationData.getNextUpdate();
						if (nextUpdate == null) {
							nextUpdate = new Date(lastTrustedUsage.getTime() + 1000); // last usage + 1s
						}

						// find the minimum for the certificate across related revocations
						if (tempMin == null || tempMin.after(nextUpdate)) {
							tempMin = nextUpdate;
						}
					}
				}

				if (goodRevocationFound) {
					continue;
				}

				// find maximum across all certificates in the chain
				if (tempMin != null) {
					if (min == null || min.before(tempMin)) {
						min = tempMin;
					}
				}
			}

		}
		return min;
	}

	private Date getMaxExtensionPeriod(AbstractTokenProxy token, List<TimestampWrapper> timestampList) {
		Date max;

		CertificateWrapper signingCertificate = token.getSigningCertificate();
		if (signingCertificate != null) {
			max = signingCertificate.getNotAfter();
		} else {
			return null;
		}

		Date maxTimestampExtensionPeriod = getMaxExtensionPeriodForTimestampList(timestampList);
		if (maxTimestampExtensionPeriod != null && maxTimestampExtensionPeriod.after(max)) {
			max = maxTimestampExtensionPeriod;
		}

		return ensureMaxExtensionTimeIsAfterValidationTime(max);
	}

	private Date getMaxExtensionPeriodForTimestampList(List<TimestampWrapper> timestampList) {
		Date max = null;

		for (TimestampWrapper timestampWrapper : timestampList) {
			if (!isValidConclusion(timestampWrapper.getId())) {
				continue;
			}
			CertificateWrapper timestampSigningCertificate = timestampWrapper.getSigningCertificate();
			if (timestampSigningCertificate != null && (max == null || timestampSigningCertificate.getNotAfter().after(max))) {
				max = timestampSigningCertificate.getNotAfter();
			}
		}

		return ensureMaxExtensionTimeIsAfterValidationTime(max);
	}

	private Date ensureMaxExtensionTimeIsAfterValidationTime(Date maxExtensionTime) {
		if (maxExtensionTime == null) {
			return null;
		}
		if (currentTime != null && currentTime.before(maxExtensionTime)) {
			return maxExtensionTime;
		}
		return null;
	}

	private boolean isValidConclusion(String tokenId) {
		Indication finalIndication = detailedReport.getFinalIndication(tokenId);
		return Indication.TOTAL_PASSED == finalIndication || Indication.PASSED == finalIndication;
	}

	private boolean containObjectWithId(List<XmlTimestampedObject> timestampedObjects, String tokenId) {
		return timestampedObjects.stream().anyMatch(o -> tokenId.equals(o.getToken().getId()));
	}

	private XmlEAAPayload buildXmlEAAPayload(AttestationWrapper attestationWrapper) {
		XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();

		AttestationPayloadProxy attestationPayloadProxy = attestationWrapper.getPayload();
		xmlEAAPayload.setIdentifier(getXmlDisclosableClaim(attestationPayloadProxy.getIdentifier()));
		xmlEAAPayload.setIssuer(getXmlDisclosableClaim(attestationPayloadProxy.getIssuer()));
		xmlEAAPayload.setSubject(getXmlDisclosableClaim(attestationPayloadProxy.getSubject()));
		xmlEAAPayload.setAudience(getXmlDisclosableClaim(attestationPayloadProxy.getAudience()));
		xmlEAAPayload.setExpiration(getXmlDisclosableClaim(attestationPayloadProxy.getExpiration()));
		xmlEAAPayload.setNotBefore(getXmlDisclosableClaim(attestationPayloadProxy.getNotBefore()));
		xmlEAAPayload.setIssuedAt(getXmlDisclosableClaim(attestationPayloadProxy.getIssuedAt()));
		xmlEAAPayload.setUpdatedAt(getXmlDisclosableClaim(attestationPayloadProxy.getUpdatedAt()));
		xmlEAAPayload.setUpdatedAt(getXmlDisclosableClaim(attestationPayloadProxy.getUpdatedAt()));
		xmlEAAPayload.setCategory(getXmlDisclosableClaim(attestationPayloadProxy.getCategory()));
		xmlEAAPayload.setVerifiableCredentialsType(getXmlDisclosableClaim(attestationPayloadProxy.getVerifiableCredentialsType()));
		StatusClaimWrapper eaaStatus = attestationPayloadProxy.getStatus();
		if (eaaStatus != null) {
			xmlEAAPayload.setStatusIndex(getXmlDisclosableClaim(eaaStatus.getIndex(), eaaStatus.isSelectivelyDisclosable()));
			xmlEAAPayload.setStatusUri(getXmlDisclosableClaim(eaaStatus.getUri(), eaaStatus.isSelectivelyDisclosable()));
			xmlEAAPayload.setStatusType(getXmlDisclosableClaim(eaaStatus.getType(), eaaStatus.isSelectivelyDisclosable()));
			xmlEAAPayload.setStatusPurpose(getXmlDisclosableClaim(eaaStatus.getPurpose(), eaaStatus.isSelectivelyDisclosable()));
		}
		xmlEAAPayload.setNonce(getXmlDisclosableClaim(attestationPayloadProxy.getNonce()));
		DeviceKeyClaimWrapper eaaDeviceKey = attestationPayloadProxy.getDeviceKey();
		if (eaaDeviceKey != null && eaaDeviceKey.getPublicKey() != null) {
			xmlEAAPayload.setDeviceKey(getXmlDisclosableClaim(eaaDeviceKey.getName(), eaaDeviceKey.isSelectivelyDisclosable(), Utils.toBase64(eaaDeviceKey.getPublicKey())));
		}
		xmlEAAPayload.setVersion(getXmlDisclosableClaim(attestationPayloadProxy.getVersion()));
		xmlEAAPayload.setDocType(getXmlDisclosableClaim(attestationPayloadProxy.getDocType()));
		ValidityInfoClaimWrapper eaaValidityInfo = attestationPayloadProxy.getValidityInfo();
		if (eaaValidityInfo != null) {
			xmlEAAPayload.setIssuedAt(getXmlDisclosableClaim(eaaValidityInfo.getSigned(), eaaValidityInfo.isSelectivelyDisclosable()));
			xmlEAAPayload.setNotBefore(getXmlDisclosableClaim(eaaValidityInfo.getValidFrom(), eaaValidityInfo.isSelectivelyDisclosable()));
			xmlEAAPayload.setAdministrativeExpirationDate(getXmlDisclosableClaim(eaaValidityInfo.getValidUntil(), eaaValidityInfo.isSelectivelyDisclosable()));
			xmlEAAPayload.setNextUpdate(getXmlDisclosableClaim(eaaValidityInfo.getExpectedUpdate(), eaaValidityInfo.isSelectivelyDisclosable()));
		}
		xmlEAAPayload.setAdministrativeIssuanceDate(getXmlDisclosableClaim(attestationPayloadProxy.getAdministrativeIssuanceDate()));
		xmlEAAPayload.setAdministrativeExpirationDate(getXmlDisclosableClaim(attestationPayloadProxy.getAdministrativeExpirationDate()));
		xmlEAAPayload.setOneTimeUse(getXmlDisclosableClaim(attestationPayloadProxy.getOneTimeUse()));
		xmlEAAPayload.setShortLived(getXmlDisclosableClaim(attestationPayloadProxy.getShortLived()));
		xmlEAAPayload.setEvidence(getXmlDisclosableClaim(attestationPayloadProxy.getEvidence()));
		if (attestationPayloadProxy.getAttestedAttributesSubject() != null) {
			AttestedAttributesSubjectClaimIdWrapper subjectId = attestationPayloadProxy.getAttestedAttributesSubject().getSubjectId();
			if (subjectId != null) {
				if (subjectId.getText() != null) {
					xmlEAAPayload.setAttestedAttributesSubjectId(getXmlDisclosableClaim(subjectId));
				}
				if (subjectId.getFamilyName() != null) {
					xmlEAAPayload.setAttestedAttributesSubjectFamilyName(getXmlDisclosableClaim(subjectId.getFamilyName()));
				}
				if (subjectId.getGivenName() != null) {
					xmlEAAPayload.setAttestedAttributesSubjectGivenName(getXmlDisclosableClaim(subjectId.getGivenName()));
				}
				if (subjectId.getDocumentNumber() != null) {
					xmlEAAPayload.setAttestedAttributesSubjectDocumentNumber(getXmlDisclosableClaim(subjectId.getDocumentNumber()));
				}
			}
			xmlEAAPayload.setAttestedAttributesSubjectPseudonym(getXmlDisclosableClaim(attestationPayloadProxy.getAttestedAttributesSubject().getSubjectPseudonym()));
			xmlEAAPayload.setAttestedAttributes(getXmlDisclosableClaim(attestationPayloadProxy.getAttestedAttributesSubject().getAttributes()));
		}

		xmlEAAPayload.setFullName(getXmlDisclosableClaim(attestationPayloadProxy.getFullName()));
		xmlEAAPayload.setGivenName(getXmlDisclosableClaim(attestationPayloadProxy.getGivenName()));
		xmlEAAPayload.setFamilyName(getXmlDisclosableClaim(attestationPayloadProxy.getFamilyName()));
		xmlEAAPayload.setMiddleName(getXmlDisclosableClaim(attestationPayloadProxy.getMiddleName()));
		xmlEAAPayload.setNickname(getXmlDisclosableClaim(attestationPayloadProxy.getNickname()));
		xmlEAAPayload.setShortName(getXmlDisclosableClaim(attestationPayloadProxy.getShortName()));
		xmlEAAPayload.setProfileUrl(getXmlDisclosableClaim(attestationPayloadProxy.getProfileUrl()));
		xmlEAAPayload.setPictureUrl(getXmlDisclosableClaim(attestationPayloadProxy.getPictureUrl()));
		xmlEAAPayload.setWebsiteUrl(getXmlDisclosableClaim(attestationPayloadProxy.getWebsiteUrl()));
		xmlEAAPayload.setEmail(getXmlDisclosableClaim(attestationPayloadProxy.getEmail()));
		xmlEAAPayload.setEmailVerified(getXmlDisclosableClaim(attestationPayloadProxy.getEmailVerified()));
		xmlEAAPayload.setGender(getXmlDisclosableClaim(attestationPayloadProxy.getGender()));
		if (attestationPayloadProxy.getBirthdate() != null) {
			xmlEAAPayload.setBirthdate(getXmlDisclosableClaim(attestationPayloadProxy.getBirthdate().getBirthdate()));
			xmlEAAPayload.setBirthdateApproximateMask(getXmlDisclosableClaim(attestationPayloadProxy.getBirthdate().getApproximateMask()));
		}
		xmlEAAPayload.setTimezone(getXmlDisclosableClaim(attestationPayloadProxy.getTimezone()));
		xmlEAAPayload.setLocale(getXmlDisclosableClaim(attestationPayloadProxy.getLocale()));
		AddressClaimWrapper userAddress = attestationPayloadProxy.getAddress();
		if (userAddress != null) {
			xmlEAAPayload.setAddressPostalAddress(getXmlDisclosableClaim(userAddress.getPostalAddress(), userAddress.isSelectivelyDisclosable()));
			xmlEAAPayload.setAddressCity(getXmlDisclosableClaim(userAddress.getCity(), userAddress.isSelectivelyDisclosable()));
			xmlEAAPayload.setAddressCountryName(getXmlDisclosableClaim(userAddress.getCountry(), userAddress.isSelectivelyDisclosable()));
			xmlEAAPayload.setAddressPostalCode(getXmlDisclosableClaim(userAddress.getPostalCode(), userAddress.isSelectivelyDisclosable()));
			xmlEAAPayload.setAddressStateOrProvince(getXmlDisclosableClaim(userAddress.getStateOrProvince(), userAddress.isSelectivelyDisclosable()));
			xmlEAAPayload.setAddressStreetAddress(getXmlDisclosableClaim(userAddress.getStreetAddress(), userAddress.isSelectivelyDisclosable()));
		}
		xmlEAAPayload.setPhoneNumber(getXmlDisclosableClaim(attestationPayloadProxy.getPhoneNumber()));
		xmlEAAPayload.setPhoneNumberVerified(getXmlDisclosableClaim(attestationPayloadProxy.getPhoneNumberVerified()));
		PlaceOfBirthClaimWrapper userPlaceOfBirth = attestationPayloadProxy.getPlaceOfBirth();
		if (userPlaceOfBirth != null) {
			xmlEAAPayload.setPlaceOfBirth(getXmlDisclosableClaim(userPlaceOfBirth, userPlaceOfBirth.isSelectivelyDisclosable()));
			xmlEAAPayload.setPlaceOfBirthCity(getXmlDisclosableClaim(userPlaceOfBirth.getCity(), userPlaceOfBirth.isSelectivelyDisclosable()));
			xmlEAAPayload.setPlaceOfBirthCountry(getXmlDisclosableClaim(userPlaceOfBirth.getCountry(), userPlaceOfBirth.isSelectivelyDisclosable()));
			xmlEAAPayload.setPlaceOfBirthRegion(getXmlDisclosableClaim(userPlaceOfBirth.getRegion(), userPlaceOfBirth.isSelectivelyDisclosable()));
		}
		xmlEAAPayload.setNationalities(getXmlDisclosableClaim(attestationPayloadProxy.getNationalities()));
		xmlEAAPayload.setBirthFamilyName(getXmlDisclosableClaim(attestationPayloadProxy.getBirthFamilyName()));
		xmlEAAPayload.setBirthGivenName(getXmlDisclosableClaim(attestationPayloadProxy.getBirthGivenName()));
		xmlEAAPayload.setBirthMiddleName(getXmlDisclosableClaim(attestationPayloadProxy.getBirthMiddleName()));
		xmlEAAPayload.setSalutation(getXmlDisclosableClaim(attestationPayloadProxy.getSalutation()));
		xmlEAAPayload.setTitle(getXmlDisclosableClaim(attestationPayloadProxy.getTitle()));
		xmlEAAPayload.setMobilePhoneNumber(getXmlDisclosableClaim(attestationPayloadProxy.getMobilePhoneNumber()));
		xmlEAAPayload.setPseudonym(getXmlDisclosableClaim(attestationPayloadProxy.getPseudonym()));

		xmlEAAPayload.setIssuingCountry(getXmlDisclosableClaim(attestationPayloadProxy.getDocumentIssuingAuthorityCountry()));
		xmlEAAPayload.setIssuingAuthority(getXmlDisclosableClaim(attestationPayloadProxy.getDocumentIssuingAuthority()));
		xmlEAAPayload.setDocumentNumber(getXmlDisclosableClaim(attestationPayloadProxy.getDocumentNumber()));
		xmlEAAPayload.setPortrait(getXmlDisclosableClaim(attestationPayloadProxy.getPortrait()));
		xmlEAAPayload.setDrivingPrivileges(getXmlDisclosableClaim(attestationPayloadProxy.getDrivingPrivileges()));
		xmlEAAPayload.setUNDistinguishingSign(getXmlDisclosableClaim(attestationPayloadProxy.getDocumentIssuingAuthorityUNDistinguishingSign()));
		xmlEAAPayload.setPersonalAdministrativeNumber(getXmlDisclosableClaim(attestationPayloadProxy.getPersonalAdministrativeNumber()));
		xmlEAAPayload.setHeight(getXmlDisclosableClaim(attestationPayloadProxy.getHeight()));
		xmlEAAPayload.setWeight(getXmlDisclosableClaim(attestationPayloadProxy.getWeight()));
		xmlEAAPayload.setEyeColour(getXmlDisclosableClaim(attestationPayloadProxy.getEyeColour()));
		xmlEAAPayload.setHairColour(getXmlDisclosableClaim(attestationPayloadProxy.getHairColour()));
		xmlEAAPayload.setResidentPostalAddress(getXmlDisclosableClaim(attestationPayloadProxy.getResidentPostalAddress()));
		xmlEAAPayload.setPortraitCaptureDate(getXmlDisclosableClaim(attestationPayloadProxy.getPortraitCaptureDate()));
		xmlEAAPayload.setAgeInYears(getXmlDisclosableClaim(attestationPayloadProxy.getAgeInYears()));
		xmlEAAPayload.setAgeBirthYear(getXmlDisclosableClaim(attestationPayloadProxy.getAgeBirthYear()));
		if (attestationPayloadProxy.getAgeEqualOrOver() != null) {
			xmlEAAPayload.getAgeOverNN().addAll(getXmlAgeOverNNClaims(attestationPayloadProxy.getAgeEqualOrOver().getAgeEqualOrOverList()));
		}
		xmlEAAPayload.getAgeOverNN().addAll(getXmlAgeOverNNClaims(attestationPayloadProxy.getAgeOverList()));
		xmlEAAPayload.setIssuingJurisdiction(getXmlDisclosableClaim(attestationPayloadProxy.getDocumentIssuingAuthorityJurisdiction()));
		xmlEAAPayload.setResidentAddressCity(getXmlDisclosableClaim(attestationPayloadProxy.getResidentAddressCity()));
		xmlEAAPayload.setResidentAddressState(getXmlDisclosableClaim(attestationPayloadProxy.getResidentAddressState()));
		xmlEAAPayload.setResidentAddressPostalCode(getXmlDisclosableClaim(attestationPayloadProxy.getResidentAddressPostalCode()));
		xmlEAAPayload.setResidentAddressCountry(getXmlDisclosableClaim(attestationPayloadProxy.getResidentAddressCountry()));
		xmlEAAPayload.getBiometricTemplate().addAll(getBiometricTemplateXXClaims(attestationPayloadProxy.getBiometricTemplateList()));
		xmlEAAPayload.setSignatureUsualMark(getXmlDisclosableClaim(attestationPayloadProxy.getSignatureUsualMark()));
		xmlEAAPayload.setFingerprint(getXmlDisclosableClaim(attestationPayloadProxy.getFingerprint()));
		xmlEAAPayload.setBusinessName(getXmlDisclosableClaim(attestationPayloadProxy.getBusinessName()));
		xmlEAAPayload.setOrganizationName(getXmlDisclosableClaim(attestationPayloadProxy.getOrganizationName()));
		xmlEAAPayload.setBirthFullName(getXmlDisclosableClaim(attestationPayloadProxy.getBirthFullName()));
		xmlEAAPayload.setProfession(getXmlDisclosableClaim(attestationPayloadProxy.getProfession()));
		xmlEAAPayload.setRelationshipFather(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipFather()));
		xmlEAAPayload.setRelationshipMother(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipMother()));
		xmlEAAPayload.setRelationshipParent(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipParent()));
		xmlEAAPayload.setRelationshipSon(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipSon()));
		xmlEAAPayload.setRelationshipDaughter(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipDaughter()));
		xmlEAAPayload.setRelationshipBrother(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipBrother()));
		xmlEAAPayload.setRelationshipSister(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipSister()));
		xmlEAAPayload.setRelationshipSibling(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipSibling()));
		xmlEAAPayload.setRelationshipSpouse(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipSpouse()));
		xmlEAAPayload.setRelationshipFatherInLaw(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipFatherInLaw()));
		xmlEAAPayload.setRelationshipMotherInLaw(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipMotherInLaw()));
		xmlEAAPayload.setRelationshipParentInLaw(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipParentInLaw()));
		xmlEAAPayload.setRelationshipSonInLaw(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipSonInLaw()));
		xmlEAAPayload.setRelationshipDaughterInLaw(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipDaughterInLaw()));
		xmlEAAPayload.setRelationshipChildInLaw(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipChildInLaw()));
		xmlEAAPayload.setRelationshipParentalAuthority(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipParentalAuthority()));
		xmlEAAPayload.setRelationshipLegalRepresentative(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipLegalRepresentative()));
		xmlEAAPayload.setRelationshipAgent(getXmlDisclosableClaim(attestationPayloadProxy.getRelationshipAgent()));
		xmlEAAPayload.setDocumentType(getXmlDisclosableClaim(attestationPayloadProxy.getClaimedDocumentType()));

		xmlEAAPayload.setIssuingAuthorityRegistrationIdentifier(getXmlDisclosableClaim(attestationPayloadProxy.getIssuingAuthorityRegistrationIdentifier()));

		xmlEAAPayload.setTrustAnchor(getXmlDisclosableClaim(attestationPayloadProxy.getTrustAnchor()));
		xmlEAAPayload.setResidentAddressStreet(getXmlDisclosableClaim(attestationPayloadProxy.getResidentAddressStreet()));
		xmlEAAPayload.setResidentAddressHouseNumber(getXmlDisclosableClaim(attestationPayloadProxy.getResidentAddressHouseNumber()));

		List<ClaimWrapper> otherClaims = attestationWrapper.getOtherClaims();
		if (Utils.isCollectionNotEmpty(otherClaims)) {
			xmlEAAPayload.getOtherClaim().addAll(otherClaims.stream().map(this::getXmlDisclosableClaim).collect(Collectors.toList()));
		}

		return xmlEAAPayload;
	}

	private List<XmlParametrizedDisclosableClaim> getXmlAgeOverNNClaims(List<AgeOverNNClaimWrapper> claimWrappers) {
		if (Utils.isCollectionEmpty(claimWrappers)) {
			return Collections.emptyList();
		}
		return claimWrappers.stream().map(this::getXmlAgeOverNNClaim).collect(Collectors.toList());
	}

	private XmlParametrizedDisclosableClaim getXmlAgeOverNNClaim(AgeOverNNClaimWrapper ageOverNNClaim) {
		XmlParametrizedDisclosableClaim xmlParametrizedDisclosableClaim = new XmlParametrizedDisclosableClaim();
		xmlParametrizedDisclosableClaim.setName(ageOverNNClaim.getName());
		xmlParametrizedDisclosableClaim.setDisclosure(ageOverNNClaim.isSelectivelyDisclosable());
		xmlParametrizedDisclosableClaim.setParameter(String.valueOf(ageOverNNClaim.getAge()));
		xmlParametrizedDisclosableClaim.setValue(ageOverNNClaim.getDisplayValue());
		return xmlParametrizedDisclosableClaim;
	}

	private List<XmlParametrizedDisclosableClaim> getBiometricTemplateXXClaims(List<BiometricTemplateXXClaimWrapper> claimWrappers) {
		if (Utils.isCollectionEmpty(claimWrappers)) {
			return Collections.emptyList();
		}
		return claimWrappers.stream().map(this::getXmlBiometricTemplateXXClaim).collect(Collectors.toList());
	}

	private XmlParametrizedDisclosableClaim getXmlBiometricTemplateXXClaim(BiometricTemplateXXClaimWrapper biometricTemplateXXClaim) {
		XmlParametrizedDisclosableClaim xmlParametrizedDisclosableClaim = new XmlParametrizedDisclosableClaim();
		xmlParametrizedDisclosableClaim.setName(biometricTemplateXXClaim.getName());
		xmlParametrizedDisclosableClaim.setDisclosure(biometricTemplateXXClaim.isSelectivelyDisclosable());
		xmlParametrizedDisclosableClaim.setParameter(biometricTemplateXXClaim.getType());
		xmlParametrizedDisclosableClaim.setValue(biometricTemplateXXClaim.getDisplayValue());
		return xmlParametrizedDisclosableClaim;
	}

	private XmlDisclosableClaim getXmlDisclosableClaim(ClaimWrapper claimWrapper) {
		return getXmlDisclosableClaim(claimWrapper, null);
	}

	private XmlDisclosableClaim getXmlDisclosableClaim(ClaimWrapper claimWrapper, Boolean selectivelyDisclosable) {
		if (claimWrapper == null) {
			return null;
		}
		Boolean isDisclosure = selectivelyDisclosable != null ? selectivelyDisclosable : claimWrapper.isSelectivelyDisclosable();
		return getXmlDisclosableClaim(getNamePath(claimWrapper), isDisclosure, claimWrapper.getDisplayValue());
	}

	private XmlDisclosableClaim getXmlDisclosableClaim(String name, Boolean selectivelyDisclosable, String displayValue) {
		XmlDisclosableClaim xmlDisclosableClaim = new XmlDisclosableClaim();
		xmlDisclosableClaim.setName(name);
		if (Utils.isTrue(selectivelyDisclosable)) {
			xmlDisclosableClaim.setDisclosure(selectivelyDisclosable);
		}
		xmlDisclosableClaim.setValue(displayValue);
		return xmlDisclosableClaim;
	}

	private String getNamePath(ClaimWrapper claimWrapper) {
		ClaimWrapper parent = claimWrapper.getParent();
		if (parent == null) {
			return claimWrapper.getName();
		}
		final StringBuilder sb = new StringBuilder(claimWrapper.getName());
		while (parent != null) {
			if (parent.isList()) {
				int position = parent.getWrapped().getEntry().indexOf(claimWrapper.getWrapped());
				sb.insert(0, position + "/");
			}
			String parentName = parent.getName();
			if (parentName != null) {
				sb.insert(0, parentName + "/");
			}
			parent = parent.getParent();
		}
		return sb.toString();
	}

}
