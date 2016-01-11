package eu.europa.esig.dss.EN319102.executor;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.EN319102.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.EN319102.validation.vpfbs.ValidationProcessForBasicSignatures;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.ValidationProcessForSignaturesWithLongTermValidationData;
import eu.europa.esig.dss.EN319102.validation.vpftsp.ValidationProcessForTimeStamps;
import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessBasicSignatures;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.validation.AbstractTokenProxy;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.report.DiagnosticData;

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

			ValidationProcessForBasicSignatures vpfbs = new ValidationProcessForBasicSignatures(diagnosticData, signature, bbbs);
			XmlValidationProcessBasicSignatures vpfbsResult = vpfbs.execute();
			signatureAnalysis.setValidationProcessBasicSignatures(vpfbsResult);

			if (ValidationLevel.TIMESTAMPS.equals(validationLevel)) {

				ValidationProcessForTimeStamps vpftsp = new ValidationProcessForTimeStamps(signature, bbbs);
				signatureAnalysis.setValidationProcessTimestamps(vpftsp.execute());

			} else if (ValidationLevel.LONG_TERM_DATA.equals(validationLevel)) {

				ValidationProcessForTimeStamps vpftsp = new ValidationProcessForTimeStamps(signature, bbbs);
				XmlValidationProcessTimestamps vpftspResult = vpftsp.execute();
				signatureAnalysis.setValidationProcessTimestamps(vpftspResult);

				ValidationProcessForSignaturesWithLongTermValidationData vpfltvd = new ValidationProcessForSignaturesWithLongTermValidationData(vpfbsResult,
						vpftspResult, diagnosticData, signature, bbbs, currentTime);
				XmlValidationProcessLongTermData vpfltvdResult = vpfltvd.execute();
				signatureAnalysis.setValidationProcessLongTermData(vpfltvdResult);

			}

			detailedReport.getSignatures().add(signatureAnalysis);
		}

		return detailedReport;
	}

	private Map<String, XmlBasicBuildingBlocks> executeAllBasicBuildingBlocks() {
		Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<String, XmlBasicBuildingBlocks>();
		switch (validationLevel) {
		case ARCHIVAL_DATA:
			process(diagnosticData.getAllArchiveTimestamps(), Context.TIMESTAMP, bbbs);
			process(diagnosticData.getAllRevocationData(), Context.REVOCATION, bbbs);
			process(diagnosticData.getAllTimestampsNotArchival(), Context.TIMESTAMP, bbbs);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
		case LONG_TERM_DATA:
			process(diagnosticData.getAllRevocationData(), Context.REVOCATION, bbbs);
			process(diagnosticData.getAllTimestampsNotArchival(), Context.TIMESTAMP, bbbs);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE, bbbs);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE, bbbs);
			break;
		case TIMESTAMPS:
			process(diagnosticData.getAllTimestampsNotArchival(), Context.TIMESTAMP, bbbs);
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
