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

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusionWithProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSemantic;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.AbstractDetailedReportBuilder;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.process.qualification.signature.SignatureQualificationBlock;
import eu.europa.esig.dss.validation.process.qualification.timestamp.TimestampQualificationBlock;
import eu.europa.esig.dss.validation.process.vpfbs.BasicSignatureValidationProcess;
import eu.europa.esig.dss.validation.process.vpftsp.TimestampBasicValidationProcess;
import eu.europa.esig.dss.validation.process.vpfltvd.ValidationProcessForSignaturesWithLongTermValidationData;
import eu.europa.esig.dss.validation.process.vpfswatsp.ValidationProcessForSignaturesWithArchivalData;
import eu.europa.esig.dss.validation.reports.DSSReportException;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds a DetailedReport for a signature validation
 */
public class DetailedReportBuilder extends AbstractDetailedReportBuilder {

	/** The target highest validation level */
	private final ValidationLevel validationLevel;

	/** Defines if the semantics information shall be included */
	private final boolean includeSemantics;

	/** Set of all used Indications (used for semantics) */
	private final Set<Indication> allIndications = new HashSet<>();

	/** Set of all used SubIndications (used for semantics) */
	private final Set<SubIndication> allSubIndications = new HashSet<>();

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentTime {@link Date} validation time
	 * @param policy {@link ValidationPolicy}
	 * @param validationLevel {@link ValidationLevel} the target highest level
	 * @param diagnosticData {@link DiagnosticData}
	 * @param includeSemantics defines if the smeantics shall be included
	 */
	public DetailedReportBuilder(I18nProvider i18nProvider, Date currentTime, ValidationPolicy policy, 
			ValidationLevel validationLevel, DiagnosticData diagnosticData, boolean includeSemantics) {
		super(i18nProvider, currentTime, policy, diagnosticData);
		this.validationLevel = validationLevel;
		this.includeSemantics = includeSemantics;
	}

	/**
	 * Builds the {@code XmlDetailedReport}
	 *
	 * @return {@link XmlDetailedReport}
	 */
	XmlDetailedReport build() {
		XmlDetailedReport detailedReport = init();
		
		detailedReport.setValidationTime(currentTime);

		List<XmlTLAnalysis> tlAnalysis = detailedReport.getTLAnalysis();

		Map<String, XmlBasicBuildingBlocks> bbbs = executeAllBasicBuildingBlocks();
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		Set<String> attachedTimestamps = new HashSet<>();
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {

			XmlSignature signatureAnalysis = new XmlSignature();

			signatureAnalysis.setId(signature.getId());
			if (signature.isCounterSignature()) {
				signatureAnalysis.setCounterSignature(true);
			}

			if (!ValidationLevel.BASIC_SIGNATURES.equals(validationLevel)) {
				attachedTimestamps.addAll(signature.getTimestampIdsList());
				signatureAnalysis.getTimestamps().addAll(getXmlTimestamps(signature.getTimestampList(), bbbs, detailedReport.getTLAnalysis()));
			}

			XmlConstraintsConclusionWithProofOfExistence validation = executeBasicValidation(signatureAnalysis, signature, signatureAnalysis.getTimestamps(), bbbs);

			if (ValidationLevel.LONG_TERM_DATA.equals(validationLevel)) {
				validation = executeLongTermValidation(signatureAnalysis, signature, bbbs);
			} else if (ValidationLevel.ARCHIVAL_DATA.equals(validationLevel)) {
				executeLongTermValidation(signatureAnalysis, signature, bbbs);
				validation = executeArchiveValidation(signatureAnalysis, signature, bbbs);
			}

			if (policy.isEIDASConstraintPresent()) {

				// Signature qualification
				CertificateWrapper signingCertificate = signature.getSigningCertificate();
				if (signingCertificate != null) {
					SignatureQualificationBlock qualificationBlock = new SignatureQualificationBlock(
							i18nProvider, validation, signingCertificate, tlAnalysis);
					signatureAnalysis.setValidationSignatureQualification(qualificationBlock.execute());
				}

			}
			
			signatureAnalysis.setConclusion(getFinalConclusion(validation));

			detailedReport.getSignatureOrTimestampOrCertificate().add(signatureAnalysis);
		}

		if (!ValidationLevel.BASIC_SIGNATURES.equals(validationLevel)) {
			for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
				if (attachedTimestamps.contains(timestamp.getId())) {
					continue;
				}

				detailedReport.getSignatureOrTimestampOrCertificate().add(buildXmlTimestamp(timestamp, bbbs, tlAnalysis));
			}
		}
		
		if (includeSemantics) {
			collectIndications(detailedReport);
			addSemantics(detailedReport);
		}

		return detailedReport;
	}

	private XmlValidationProcessBasicSignature executeBasicValidation(XmlSignature signatureAnalysis, SignatureWrapper signature,
			List<XmlTimestamp> xmlTimestamps, Map<String, XmlBasicBuildingBlocks> bbbs) {
		BasicSignatureValidationProcess vpfbs = new BasicSignatureValidationProcess(
				i18nProvider, diagnosticData, signature, xmlTimestamps, bbbs);
		XmlValidationProcessBasicSignature bs = vpfbs.execute();
		signatureAnalysis.setValidationProcessBasicSignature(bs);
		return bs;
	}

	private List<XmlTimestamp> getXmlTimestamps(List<TimestampWrapper> timestamps, Map<String, XmlBasicBuildingBlocks> bbbs, List<XmlTLAnalysis> tlAnalysis) {
		List<XmlTimestamp> results = new ArrayList<>();
		for (TimestampWrapper timestamp : timestamps) {
			results.add(buildXmlTimestamp(timestamp, bbbs, tlAnalysis));
		}
		return results;
	}

	private XmlTimestamp buildXmlTimestamp(TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs, List<XmlTLAnalysis> tlAnalysis) {
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setId(timestamp.getId());

		TimestampBasicValidationProcess vpftsp = new TimestampBasicValidationProcess(i18nProvider, diagnosticData, timestamp, bbbs);
		xmlTimestamp.setValidationProcessTimestamp(vpftsp.execute());

		// Timestamp qualification
		if (policy.isEIDASConstraintPresent()) {
			TimestampQualificationBlock timestampQualificationBlock = new TimestampQualificationBlock(i18nProvider, timestamp, tlAnalysis);
			xmlTimestamp.setValidationTimestampQualification(timestampQualificationBlock.execute());
		}
		return xmlTimestamp;
	}

	private XmlValidationProcessLongTermData executeLongTermValidation(XmlSignature signatureAnalysis, SignatureWrapper signature,
			Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForSignaturesWithLongTermValidationData vpfltvd = new ValidationProcessForSignaturesWithLongTermValidationData(
				i18nProvider, signatureAnalysis, diagnosticData, signature, bbbs, policy, currentTime);
		XmlValidationProcessLongTermData vpfltvdResult = vpfltvd.execute();
		signatureAnalysis.setValidationProcessLongTermData(vpfltvdResult);
		return vpfltvdResult;
	}

	private XmlValidationProcessArchivalData executeArchiveValidation(XmlSignature signatureAnalysis, SignatureWrapper signature,
			Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForSignaturesWithArchivalData vpfswad = new ValidationProcessForSignaturesWithArchivalData(i18nProvider, signatureAnalysis, 
				signature, diagnosticData, bbbs, policy, currentTime);
		XmlValidationProcessArchivalData vpfswadResult = vpfswad.execute();
		signatureAnalysis.setValidationProcessArchivalData(vpfswadResult);
		return vpfswadResult;
	}

	private Map<String, XmlBasicBuildingBlocks> executeAllBasicBuildingBlocks() {
		Map<String, XmlBasicBuildingBlocks> bbbs = new LinkedHashMap<>();
		switch (validationLevel) {
		case ARCHIVAL_DATA:
		case LONG_TERM_DATA:
			process(diagnosticData.getAllRevocationData(), Context.REVOCATION, bbbs);
			process(diagnosticData.getTimestampList(), Context.TIMESTAMP, bbbs);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
			break;
		case TIMESTAMPS:
			process(diagnosticData.getTimestampList(), Context.TIMESTAMP, bbbs);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
			break;
		case BASIC_SIGNATURES:
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
			break;
		default:
			throw new IllegalArgumentException("Unsupported validation level " + validationLevel);
		}
		return bbbs;
	}
	
	private XmlConclusion getFinalConclusion(XmlConstraintsConclusion constraintConclusion) {
		XmlConclusion xmlConclusion = new XmlConclusion();
		Indication indication = getFinalIndication(constraintConclusion.getConclusion().getIndication());
		xmlConclusion.setIndication(indication);
		SubIndication subIndication = constraintConclusion.getConclusion().getSubIndication();
		xmlConclusion.setSubIndication(subIndication);
		return xmlConclusion;
	}
	
	private Indication getFinalIndication(Indication highestIndication) {
		switch (highestIndication) {
			case PASSED:
				return Indication.TOTAL_PASSED;
			case INDETERMINATE:
				return Indication.INDETERMINATE;
			case FAILED:
				return Indication.TOTAL_FAILED;
			default:
				throw new DSSReportException(String.format("The Indication '%s' is not supported!", highestIndication));
		}
	}
	
	private void collectIndications(XmlDetailedReport detailedReport) {
		for (Serializable xmlObject : detailedReport.getSignatureOrTimestampOrCertificate()) {
			if (xmlObject instanceof XmlSignature) {
				collectIndications((XmlSignature) xmlObject);
			} else if (xmlObject instanceof XmlTimestamp) {
				collectIndications((XmlTimestamp) xmlObject);
			}
		}
		for (XmlBasicBuildingBlocks bbb : detailedReport.getBasicBuildingBlocks()) {
			collectIndications(bbb);
		}
	}

	private void collectIndications(XmlSignature xmlSignature) {
		collectIndications(xmlSignature.getConclusion());
		collectIndications(xmlSignature.getValidationProcessBasicSignature());
		collectIndications(xmlSignature.getValidationProcessLongTermData());
		collectIndications(xmlSignature.getValidationProcessArchivalData());
		for (XmlTimestamp xmlTimestamp : xmlSignature.getTimestamps()) {
			collectIndications(xmlTimestamp);
		}
	}

	private void collectIndications(XmlTimestamp xmlTimestamp) {
		collectIndications(xmlTimestamp.getValidationProcessTimestamp());
	}

	private void collectIndications(XmlBasicBuildingBlocks bbb) {
		collectIndications(bbb.getFC());
		collectIndications(bbb.getISC());
		collectIndications(bbb.getVCI());
		collectIndications(bbb.getXCV());
		if (bbb.getXCV() != null) {
			for (XmlSubXCV subXCV : bbb.getXCV().getSubXCV()) {
				collectIndications(subXCV);
				collectIndications(subXCV.getRFC());
				collectIndications(subXCV.getCRS());
				if (subXCV.getCRS() != null) {
					for (XmlRAC rac : subXCV.getCRS().getRAC()) {
						collectIndications(rac);
					}
				}
			}
		}
		collectIndications(bbb.getCV());
		collectIndications(bbb.getSAV());
		collectIndications(bbb.getPSV());
		collectIndications(bbb.getPCV());
		collectIndications(bbb.getVTS());
	}
	
	private void collectIndications(XmlConstraintsConclusion xmlConstraintsConclusion) {
		if (xmlConstraintsConclusion != null) {
			collectIndications(xmlConstraintsConclusion.getConclusion());
		}
	}
	
	private void collectIndications(XmlConclusion xmlConclusion) {
		if (xmlConclusion != null) {
			Indication indication = xmlConclusion.getIndication();
			if (indication != null) {
				allIndications.add(xmlConclusion.getIndication());
				
				SubIndication subIndication = xmlConclusion.getSubIndication();
				if (subIndication != null) {
					allSubIndications.add(subIndication);
				}
			}
		}
	}

	private void addSemantics(XmlDetailedReport detailedReport) {
		
		for (Indication indication : allIndications) {
			XmlSemantic semantic = new XmlSemantic();
			semantic.setKey(indication.name());
			semantic.setValue(i18nProvider.getMessage(MessageTag.getSemantic(indication.name())));
			detailedReport.getSemantic().add(semantic);
		}

		for (SubIndication subIndication : allSubIndications) {
			XmlSemantic semantic = new XmlSemantic();
			semantic.setKey(subIndication.name());
			semantic.setValue(i18nProvider.getMessage(MessageTag.getSemantic(subIndication.name())));
			detailedReport.getSemantic().add(semantic);
		}

	}

}
