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
package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusionWithProofOfExistence;
import eu.europa.esig.dss.jaxb.detailedreport.XmlDetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessBasicSignatures;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.qualification.signature.SignatureQualificationBlock;
import eu.europa.esig.dss.validation.process.vpfbs.ValidationProcessForBasicSignatures;
import eu.europa.esig.dss.validation.process.vpfltvd.ValidationProcessForSignaturesWithLongTermValidationData;
import eu.europa.esig.dss.validation.process.vpfswatsp.ValidationProcessForSignaturesWithArchivalData;
import eu.europa.esig.dss.validation.process.vpftsp.ValidationProcessForTimeStamps;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class DetailedReportBuilder extends AbstractDetailedReportBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(DetailedReportBuilder.class);

	private final ValidationLevel validationLevel;

	public DetailedReportBuilder(Date currentTime, ValidationPolicy policy, ValidationLevel validationLevel, DiagnosticData diagnosticData) {
		super(diagnosticData, policy, currentTime);
		this.validationLevel = validationLevel;
	}

	XmlDetailedReport build() {
		XmlDetailedReport detailedReport = init();

		Map<String, XmlBasicBuildingBlocks> bbbs = executeAllBasicBuildingBlocks();
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {

			XmlSignature signatureAnalysis = new XmlSignature();

			signatureAnalysis.setId(signature.getId());
			if (signature.isCounterSignature()) {
				signatureAnalysis.setCounterSignature(true);
			}

			XmlConstraintsConclusionWithProofOfExistence validation = executeBasicValidation(signatureAnalysis, signature, bbbs);

			if (ValidationLevel.TIMESTAMPS.equals(validationLevel)) {
				executeTimestampsValidation(signatureAnalysis, signature, bbbs);
			} else if (ValidationLevel.LONG_TERM_DATA.equals(validationLevel)) {
				executeTimestampsValidation(signatureAnalysis, signature, bbbs);
				validation = executeLongTermValidation(signatureAnalysis, signature, bbbs);
			} else if (ValidationLevel.ARCHIVAL_DATA.equals(validationLevel)) {
				executeTimestampsValidation(signatureAnalysis, signature, bbbs);
				executeLongTermValidation(signatureAnalysis, signature, bbbs);
				validation = executeArchiveValidation(signatureAnalysis, signature, bbbs);
			}

			if (policy.isEIDASConstraintPresent()) {
				try {
					CertificateWrapper signingCertificate = signature.getSigningCertificate();
					if (signingCertificate != null) {
						SignatureQualificationBlock qualificationBlock = new SignatureQualificationBlock(signature.getId(), validation, signingCertificate,
								detailedReport.getTLAnalysis(), diagnosticData.getLOTLCountryCode());
						signatureAnalysis.setValidationSignatureQualification(qualificationBlock.execute());
					}
				} catch (Exception e) {
					LOG.error("Unable to determine the signature qualification", e);
				}
			}

			detailedReport.getSignatures().add(signatureAnalysis);
		}

		return detailedReport;
	}

	private XmlValidationProcessBasicSignatures executeBasicValidation(XmlSignature signatureAnalysis, SignatureWrapper signature,
			Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForBasicSignatures vpfbs = new ValidationProcessForBasicSignatures(diagnosticData, signature, bbbs);
		XmlValidationProcessBasicSignatures bs = vpfbs.execute();
		signatureAnalysis.setValidationProcessBasicSignatures(bs);
		return bs;
	}

	private void executeTimestampsValidation(XmlSignature signatureAnalysis, SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs) {
		List<TimestampWrapper> allTimestamps = signature.getTimestampList();
		for (TimestampWrapper timestamp : allTimestamps) {
			ValidationProcessForTimeStamps vpftsp = new ValidationProcessForTimeStamps(timestamp, bbbs);
			signatureAnalysis.getValidationProcessTimestamps().add(vpftsp.execute());
		}
	}

	private XmlValidationProcessLongTermData executeLongTermValidation(XmlSignature signatureAnalysis, SignatureWrapper signature,
			Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForSignaturesWithLongTermValidationData vpfltvd = new ValidationProcessForSignaturesWithLongTermValidationData(signatureAnalysis,
				diagnosticData, signature, bbbs, policy, currentTime);
		XmlValidationProcessLongTermData vpfltvdResult = vpfltvd.execute();
		signatureAnalysis.setValidationProcessLongTermData(vpfltvdResult);
		return vpfltvdResult;
	}

	private XmlValidationProcessArchivalData executeArchiveValidation(XmlSignature signatureAnalysis, SignatureWrapper signature,
			Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForSignaturesWithArchivalData vpfswad = new ValidationProcessForSignaturesWithArchivalData(signatureAnalysis, signature,
				diagnosticData, bbbs, policy, currentTime);
		XmlValidationProcessArchivalData vpfswadResult = vpfswad.execute();
		signatureAnalysis.setValidationProcessArchivalData(vpfswadResult);
		return vpfswadResult;
	}

	private Map<String, XmlBasicBuildingBlocks> executeAllBasicBuildingBlocks() {
		Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<String, XmlBasicBuildingBlocks>();
		switch (validationLevel) {
		case ARCHIVAL_DATA:
		case LONG_TERM_DATA:
			process(diagnosticData.getAllRevocationData(), Context.REVOCATION, bbbs);
			process(diagnosticData.getTimestampSet(), Context.TIMESTAMP, bbbs);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
			break;
		case TIMESTAMPS:
			process(diagnosticData.getTimestampSet(), Context.TIMESTAMP, bbbs);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
			break;
		case BASIC_SIGNATURES:
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
			break;
		default:
			throw new DSSException("Unsupported validation level " + validationLevel);
		}
		return bbbs;
	}

}
