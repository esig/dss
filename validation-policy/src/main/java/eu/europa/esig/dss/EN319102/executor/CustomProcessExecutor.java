package eu.europa.esig.dss.EN319102.executor;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.EN319102.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.EN319102.validation.bs.ValidationProcessForBasicSignatures;
import eu.europa.esig.dss.EN319102.validation.tsp.ValidationProcessForTimeStamps;
import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.validation.AbstractTokenProxy;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;

public class CustomProcessExecutor implements ProcessExecutor {

	private Date currentDate = new Date();
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;

	private eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData jaxbDiagnosticData;
	private DiagnosticData diagnosticData;

	private ValidationPolicy policy;

	@Override
	public void getCurrentTime(Date currentDate) {
		this.currentDate = currentDate;
	}

	@Override
	public void setDiagnosticData(eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	@Override
	public void setValidationPolicy(ValidationPolicy policy) {
		this.policy = policy;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}

	@Override
	public Reports execute() {

		assert jaxbDiagnosticData != null && policy != null && currentDate != null && validationLevel != null;

		diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReport detailedReport = new DetailedReport();

		Map<String, XmlBasicBuildingBlocks> bbbs = executeAllBasicBuildingBlocks();

		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {

			ValidationProcessForBasicSignatures vpfbs = new ValidationProcessForBasicSignatures(diagnosticData, bbbs.get(signature.getId()), bbbs);

			XmlSignature signatureAnalysis = new XmlSignature();
			signatureAnalysis.setId(signature.getId());
			signatureAnalysis.setType(signature.getType());
			signatureAnalysis.setValidationProcessBasicSignatures(vpfbs.execute());

			if (ValidationLevel.TIMESTAMPS.equals(validationLevel)) {
				Set<TimestampWrapper> allTimestampsNotArchival = diagnosticData.getAllTimestampsNotArchival(signature.getId());
				for (TimestampWrapper tsp : allTimestampsNotArchival) {
					ValidationProcessForTimeStamps vpftsp = new ValidationProcessForTimeStamps(bbbs.get(tsp.getId()));
					signatureAnalysis.getValidationProcessTimestamps().add(vpftsp.execute());
				}
			}

			if (ValidationLevel.LONG_TERM_DATA.equals(validationLevel)) {

			}

			detailedReport.getSignatures().add(signatureAnalysis);
		}

		return null;
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
			break;
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
			BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, token, currentDate, policy, context);
			XmlBasicBuildingBlocks result = bbb.execute();
			bbbs.put(token.getId(), result);
		}
	}

}
