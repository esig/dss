package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.validation.process.vpfbs.ValidationProcessForBasicSignatures;
import eu.europa.esig.dss.validation.process.vpfltvd.ValidationProcessForSignaturesWithLongTermValidationData;
import eu.europa.esig.dss.validation.process.vpfswatsp.ValidationProcessForSignaturesWithArchivalData;
import eu.europa.esig.dss.validation.process.vpftsp.ValidationProcessForTimeStamps;
import eu.europa.esig.dss.validation.reports.wrapper.AbstractTokenProxy;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class DetailedReportBuilder {

	private final Date currentTime;
	private final ValidationPolicy policy;
	private final ValidationLevel validationLevel;
	private final DiagnosticData diagnosticData;

	public DetailedReportBuilder(Date currentTime, ValidationPolicy policy, ValidationLevel validationLevel, DiagnosticData diagnosticData) {
		this.currentTime = currentTime;
		this.policy = policy;
		this.validationLevel = validationLevel;
		this.diagnosticData = diagnosticData;
	}

	DetailedReport build() {
		DetailedReport detailedReport = new DetailedReport();

		Map<String, XmlBasicBuildingBlocks> bbbs = executeAllBasicBuildingBlocks();

		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {

			XmlSignature signatureAnalysis = new XmlSignature();

			signatureAnalysis.setId(signature.getId());
			signatureAnalysis.setType(signature.getType());

			executeBasicValidation(signatureAnalysis, signature, diagnosticData, bbbs);

			if (ValidationLevel.TIMESTAMPS.equals(validationLevel)) {
				executeTimestampsValidation(signatureAnalysis, signature, bbbs);
			} else if (ValidationLevel.LONG_TERM_DATA.equals(validationLevel)) {
				executeTimestampsValidation(signatureAnalysis, signature, bbbs);
				executeLongTermValidation(signatureAnalysis, signature, bbbs);
			} else if (ValidationLevel.ARCHIVAL_DATA.equals(validationLevel)) {
				executeTimestampsValidation(signatureAnalysis, signature, bbbs);
				executeLongTermValidation(signatureAnalysis, signature, bbbs);
				executeArchiveValidation(signatureAnalysis, signature, bbbs);
			}

			detailedReport.getSignature().add(signatureAnalysis);
		}

		return detailedReport;
	}

	private void executeBasicValidation(XmlSignature signatureAnalysis, SignatureWrapper signature, DiagnosticData diagnosticData2,
			Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForBasicSignatures vpfbs = new ValidationProcessForBasicSignatures(diagnosticData, signature, bbbs);
		signatureAnalysis.setValidationProcessBasicSignatures(vpfbs.execute());
	}

	private void executeTimestampsValidation(XmlSignature signatureAnalysis, SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs) {
		List<TimestampWrapper> allTimestamps = signature.getTimestampList(); // PVA : all timestamps here ? Used in LTV
		for (TimestampWrapper timestamp : allTimestamps) {
			ValidationProcessForTimeStamps vpftsp = new ValidationProcessForTimeStamps(timestamp, bbbs);
			signatureAnalysis.getValidationProcessTimestamps().add(vpftsp.execute());
		}
	}

	private void executeLongTermValidation(XmlSignature signatureAnalysis, SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForSignaturesWithLongTermValidationData vpfltvd = new ValidationProcessForSignaturesWithLongTermValidationData(signatureAnalysis,
				diagnosticData, signature, bbbs, policy, currentTime);
		XmlValidationProcessLongTermData vpfltvdResult = vpfltvd.execute();
		signatureAnalysis.setValidationProcessLongTermData(vpfltvdResult);
	}

	private void executeArchiveValidation(XmlSignature signatureAnalysis, SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs) {
		ValidationProcessForSignaturesWithArchivalData vpfswad = new ValidationProcessForSignaturesWithArchivalData(signatureAnalysis, signature,
				diagnosticData, bbbs, policy, currentTime);
		XmlValidationProcessArchivalData vpfswadResult = vpfswad.execute();
		signatureAnalysis.setValidationProcessArchivalData(vpfswadResult);
	}

	private Map<String, XmlBasicBuildingBlocks> executeAllBasicBuildingBlocks() {
		Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<String, XmlBasicBuildingBlocks>();
		switch (validationLevel) {
		case ARCHIVAL_DATA:
		case LONG_TERM_DATA:
			process(diagnosticData.getAllRevocationData(), Context.REVOCATION, bbbs);
			process(diagnosticData.getAllTimestamps(), Context.TIMESTAMP, bbbs);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
			break;
		case TIMESTAMPS:
			process(diagnosticData.getAllTimestamps(), Context.TIMESTAMP, bbbs);
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

	private void process(Set<? extends AbstractTokenProxy> tokensToProcess, Context context, Map<String, XmlBasicBuildingBlocks> bbbs) {
		for (AbstractTokenProxy token : tokensToProcess) {
			BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, token, currentTime, policy, context);
			XmlBasicBuildingBlocks result = bbb.execute();
			bbbs.put(token.getId(), result);
		}
	}

}
