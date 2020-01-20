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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusionWithProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
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
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.AbstractDetailedReportBuilder;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.process.qualification.signature.SignatureQualificationBlock;
import eu.europa.esig.dss.validation.process.qualification.timestamp.TimestampQualificationBlock;
import eu.europa.esig.dss.validation.process.vpfbs.ValidationProcessForBasicSignature;
import eu.europa.esig.dss.validation.process.vpfltvd.ValidationProcessForSignaturesWithLongTermValidationData;
import eu.europa.esig.dss.validation.process.vpfswatsp.ValidationProcessForSignaturesWithArchivalData;
import eu.europa.esig.dss.validation.process.vpftsp.ValidationProcessForTimeStamp;

public class DetailedReportBuilder extends AbstractDetailedReportBuilder {

	private final ValidationLevel validationLevel;

	public DetailedReportBuilder(I18nProvider i18nProvider, Date currentTime, ValidationPolicy policy, 
			ValidationLevel validationLevel, DiagnosticData diagnosticData) {
		super(i18nProvider, currentTime, policy, diagnosticData);
		this.validationLevel = validationLevel;
	}

	XmlDetailedReport build() {
		XmlDetailedReport detailedReport = init();

		List<XmlTLAnalysis> tlAnalysis = detailedReport.getTLAnalysis();

		Map<String, XmlBasicBuildingBlocks> bbbs = executeAllBasicBuildingBlocks();
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		Set<String> attachedTimestamps = new HashSet<String>();
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {

			XmlSignature signatureAnalysis = new XmlSignature();

			signatureAnalysis.setId(signature.getId());
			if (signature.isCounterSignature()) {
				signatureAnalysis.setCounterSignature(true);
			}

			XmlConstraintsConclusionWithProofOfExistence validation = executeBasicValidation(signatureAnalysis, signature, bbbs);

			if (ValidationLevel.TIMESTAMPS.equals(validationLevel)) {
				attachedTimestamps.addAll(signature.getTimestampIdsList());
				signatureAnalysis.getTimestamp().addAll(getXmlTimestamps(signature.getTimestampList(), bbbs, detailedReport.getTLAnalysis()));
			} else if (ValidationLevel.LONG_TERM_DATA.equals(validationLevel)) {
				attachedTimestamps.addAll(signature.getTimestampIdsList());
				signatureAnalysis.getTimestamp().addAll(getXmlTimestamps(signature.getTimestampList(), bbbs, detailedReport.getTLAnalysis()));
				validation = executeLongTermValidation(signatureAnalysis, signature, bbbs);
			} else if (ValidationLevel.ARCHIVAL_DATA.equals(validationLevel)) {
				attachedTimestamps.addAll(signature.getTimestampIdsList());
				signatureAnalysis.getTimestamp().addAll(getXmlTimestamps(signature.getTimestampList(), bbbs, detailedReport.getTLAnalysis()));
				executeLongTermValidation(signatureAnalysis, signature, bbbs);
				validation = executeArchiveValidation(signatureAnalysis, signature, bbbs);
			}

			if (policy.isEIDASConstraintPresent()) {

				// Signature qualification
				CertificateWrapper signingCertificate = signature.getSigningCertificate();
				if (signingCertificate != null) {
					SignatureQualificationBlock qualificationBlock = new SignatureQualificationBlock(i18nProvider, signature.getId(), validation,
							signingCertificate, tlAnalysis);
					signatureAnalysis.setValidationSignatureQualification(qualificationBlock.execute());
				}

			}

			detailedReport.getSignatureOrTimestampOrCertificate().add(signatureAnalysis);
		}

		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (attachedTimestamps.contains(timestamp.getId())) {
				continue;
			}

			detailedReport.getSignatureOrTimestampOrCertificate().add(buildXmlTimestamp(timestamp, bbbs, tlAnalysis));
		}

		return detailedReport;
	}

	private XmlValidationProcessBasicSignature executeBasicValidation(XmlSignature signatureAnalysis, SignatureWrapper signature,
			Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForBasicSignature vpfbs = new ValidationProcessForBasicSignature(i18nProvider, diagnosticData, signature, bbbs);
		XmlValidationProcessBasicSignature bs = vpfbs.execute();
		signatureAnalysis.setValidationProcessBasicSignature(bs);
		return bs;
	}

	private List<XmlTimestamp> getXmlTimestamps(List<TimestampWrapper> timestamps, Map<String, XmlBasicBuildingBlocks> bbbs, List<XmlTLAnalysis> tlAnalysis) {
		List<XmlTimestamp> results = new ArrayList<XmlTimestamp>();
		for (TimestampWrapper timestamp : timestamps) {
			results.add(buildXmlTimestamp(timestamp, bbbs, tlAnalysis));
		}
		return results;
	}

	private XmlTimestamp buildXmlTimestamp(TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs, List<XmlTLAnalysis> tlAnalysis) {
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setId(timestamp.getId());

		ValidationProcessForTimeStamp vpftsp = new ValidationProcessForTimeStamp(i18nProvider, diagnosticData, timestamp, bbbs);
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
		Map<String, XmlBasicBuildingBlocks> bbbs = new LinkedHashMap<String, XmlBasicBuildingBlocks>();
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

}
