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
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplereport.jaxb.XmlSemantic;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestampLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.AbstractSimpleReportBuilder;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data and detailed validation report.
 */
public class SimpleReportBuilder extends AbstractSimpleReportBuilder {

	/** i18nProvider */
	private final I18nProvider i18nProvider;

	/** Defines if the semantics shall be included */
	private final boolean includeSemantics;

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
		super(currentTime, policy, diagnosticData, detailedReport);
		this.i18nProvider = i18nProvider;
		this.includeSemantics = includeSemantics;
	}

	/**
	 * This method generates the validation simpleReport.
	 *
	 * @return the object representing {@code XmlSimpleReport}
	 */
	@Override
	public XmlSimpleReport build() {

		validSignatureCount = 0;
		totalSignatureCount = 0;

		poe = new POEExtraction();
		poe.init(diagnosticData, diagnosticData.getValidationDate());
		poe.collectAllPOE(diagnosticData.getTimestampList());

		XmlSimpleReport simpleReport = super.build();

		boolean containerInfoPresent = diagnosticData.isContainerInfoPresent();

		Set<String> attachedTimestampIds = new HashSet<>();
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			attachedTimestampIds.addAll(signature.getTimestampIdsList());
			simpleReport.getSignatureOrTimestamp().add(getSignature(signature, containerInfoPresent));
		}

		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (attachedTimestampIds.contains(timestamp.getId())) {
				continue;
			}
			simpleReport.getSignatureOrTimestamp().add(getXmlTimestamp(timestamp));
		}

		addStatistics(simpleReport);

		if (includeSemantics) {
			addSemantics(simpleReport);
		}

		return simpleReport;
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

		XmlDetails validationDetails = getValidationDetails(signatureId);
		if (isNotEmpty(validationDetails)) {
			xmlSignature.setValidationDetails(validationDetails);
		}

		XmlDetails qualificationDetails = getQualificationDetails(signatureId);
		if (isNotEmpty(qualificationDetails)) {
			xmlSignature.setQualificationDetails(qualificationDetails);
		}

		if (container) {
			xmlSignature.setFilename(signature.getSignatureFilename());
		}

		Indication indication = detailedReport.getFinalIndication(signatureId);
		if (Indication.TOTAL_PASSED.equals(indication)) {
			validSignatureCount++;
			determineExtensionPeriod(xmlSignature);
		}
		xmlSignature.setIndication(indication);
		finalIndications.add(indication);

		SubIndication subIndication = detailedReport.getFinalSubIndication(signatureId);
		if (subIndication != null) {
			xmlSignature.setSubIndication(subIndication);
			finalSubIndications.add(subIndication);
		}

		addSignatureProfile(xmlSignature);

		xmlSignature.setCertificateChain(getCertChain(signatureId));

		List<TimestampWrapper> timestampList = signature.getTimestampList();
		if (Utils.isCollectionNotEmpty(timestampList)) {
			XmlTimestamps xmlTimestamps = new XmlTimestamps();
			for (TimestampWrapper timestamp : timestampList) {
				Indication tstValidationIndication = detailedReport.getTimestampValidationIndication(timestamp.getId());
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

	private XmlDetails getValidationDetails(String tokenId) {
		XmlDetails validationDetails = new XmlDetails();
		validationDetails.getError().addAll(convert(detailedReport.getValidationErrors(tokenId)));
		validationDetails.getWarning().addAll(convert(detailedReport.getValidationWarnings(tokenId)));
		validationDetails.getInfo().addAll(convert(detailedReport.getValidationInfos(tokenId)));
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
				xmlCertificateChain.getCertificate().add(certificate);
			}
		}
		return xmlCertificateChain;
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
			for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope scopeType : signatureScopes) {
				XmlSignatureScope scope = new XmlSignatureScope();
				scope.setName(scopeType.getName());
				scope.setScope(scopeType.getScope().name());
				scope.setValue(scopeType.getDescription());
				xmlSignature.getSignatureScope().add(scope);
			}
		}
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

		Indication indication = detailedReport.getBasicBuildingBlocksIndication(timestampId);
		xmlTimestamp.setIndication(indication);
		finalIndications.add(indication);

		SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(timestampId);
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

		XmlDetails validationDetails = getValidationDetails(timestampId);
		if (isNotEmpty(validationDetails)) {
			xmlTimestamp.setValidationDetails(validationDetails);
		}

		XmlDetails qualificationDetails = getQualificationDetails(timestampId);
		if (isNotEmpty(qualificationDetails)) {
			xmlTimestamp.setQualificationDetails(qualificationDetails);
		}

		return xmlTimestamp;
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
		xmlSignature.setExtensionPeriodMin(getMinExtensionPeriod(signatureWrapper));
		xmlSignature.setExtensionPeriodMax(getMaxExtensionPeriod(signatureWrapper));
	}

	private Date getMinExtensionPeriod(SignatureWrapper signatureWrapper) {

		Date min = null;
		List<List<CertificateWrapper>> chains = new ArrayList<>();
		chains.add(signatureWrapper.getCertificateChain());
		List<RelatedRevocationWrapper> relatedRevocations = signatureWrapper.foundRevocations().getRelatedRevocationData();
		for (RevocationWrapper revocation : relatedRevocations) {
			chains.add(revocation.getCertificateChain());
		}

		for (List<CertificateWrapper> certificateChain : chains) {
			Date certChainMin = getMinExtensionPeriodForChain(certificateChain, null);
			if (certChainMin != null) {
				if (min == null || min.after(certChainMin)) {
					min = certChainMin;
				}
			}
		}

		List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
		for (TimestampWrapper timestampWrapper : timestampList) {
			Date certChainMin = getMinExtensionPeriodForChain(timestampWrapper.getCertificateChain(), timestampWrapper.getProductionTime());
			if (certChainMin != null) {
				if (min == null || min.after(certChainMin)) {
					min = certChainMin;
				}
			}
		}

		return min;
	}

	private Date getMinExtensionPeriodForChain(List<CertificateWrapper> certificateChain, Date usageTime) {
		Date min = null;
		for (CertificateWrapper certificateWrapper : certificateChain) {
			if (certificateWrapper.isTrusted()) {
				break;
			}

			Date lastTrustedUsage = null;
			if (usageTime != null) {
				lastTrustedUsage = usageTime;
			} else {
				lastTrustedUsage = poe.getLowestPOETime(certificateWrapper.getId());
			}

			if (ValidationProcessUtils.isRevocationCheckRequired(certificateWrapper, lastTrustedUsage)) {
				Date tempMin = null;
				List<CertificateRevocationWrapper> certificateRevocationData = certificateWrapper.getCertificateRevocationData();
				for (CertificateRevocationWrapper revocationData : certificateRevocationData) {
					if (lastTrustedUsage.after(revocationData.getThisUpdate())) {

						Date nextUpdate = revocationData.getNextUpdate();
						if (nextUpdate == null) {
							nextUpdate = new Date(lastTrustedUsage.getTime() + 1000); // last usage + 1s
						}

						if (tempMin == null || tempMin.after(nextUpdate)) {
							tempMin = nextUpdate;
						}
					}
				}

				if (tempMin != null) {
					if (min == null || min.after(tempMin)) {
						min = tempMin;
					}
				}
			}
		}
		return min;
	}

	private Date getMaxExtensionPeriod(SignatureWrapper signatureWrapper) {
		Date max = null;

		CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
		if (signingCertificate != null) {
			max = signingCertificate.getNotAfter();
		}

		List<TimestampWrapper> timestampList = signatureWrapper.getAllTimestampsProducedAfterSignatureCreation();
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (!timestampWrapper.isSignatureValid()) {
				continue;
			}
			CertificateWrapper timestampSigningCertificate = timestampWrapper.getSigningCertificate();
			List<SignatureWrapper> timestampedSignatures = timestampWrapper.getTimestampedSignatures();
			if (timestampSigningCertificate != null && timestampedSignatures.contains(signatureWrapper)) {
				if (timestampSigningCertificate.getNotAfter().after(max)) {
					max = timestampSigningCertificate.getNotAfter();
				}
			}
		}

		return max;
	}

}
