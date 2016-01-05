package eu.europa.esig.dss.EN319102.executor;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.EN319102.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.validation.AbstractTokenProxy;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;

public class CustomProcessExecutor implements ProcessExecutor {

	private Date currentDate = new Date();
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;

	private eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData jaxbDiagnosticData;
	private DiagnosticData diagnosticData;

	private ValidationPolicy policy;

	private Map<String, BasicBuildingBlocks> bbbs = new HashMap<String, BasicBuildingBlocks>();

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

		executeAllBasicBuildingBlocks();

		return null;
	}

	private void executeAllBasicBuildingBlocks() {
		switch (validationLevel) {
		case ARCHIVAL_DATA:
			process(diagnosticData.getAllArchiveTimestamps(), Context.TIMESTAMP);
			process(diagnosticData.getAllRevocationData(), Context.REVOCATION);
			process(diagnosticData.getAllTimestampsNotArchival(), Context.TIMESTAMP);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE);
			break;
		case LONG_TERM_DATA:
			process(diagnosticData.getAllRevocationData(), Context.REVOCATION);
			process(diagnosticData.getAllTimestampsNotArchival(), Context.TIMESTAMP);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE);
			break;
		case TIMESTAMPS:
			process(diagnosticData.getAllTimestampsNotArchival(), Context.TIMESTAMP);
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE);
			break;
		case BASIC_SIGNATURES:
			process(diagnosticData.getAllSignatures(), Context.SIGNATURE);
			process(diagnosticData.getAllCounterSignatures(), Context.COUNTER_SIGNATURE);
			break;
		default:
			throw new DSSException("Unsupported validation level " + validationLevel);
		}
	}

	private void process(Set<? extends AbstractTokenProxy> tokensToProcess, Context context) {
		// TODO Auto-generated method stub

	}

}
