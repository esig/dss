package eu.europa.esig.dss.validation.executor;

import java.util.Date;

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.Reports;

public class CertificateProcessExecutor implements ProcessExecutor {

	private Date currentDate;
	private DiagnosticData diagnosticDataJaxb;
	private ValidationPolicy policy;

	@Override
	public void setCurrentTime(Date currentDate) {
		this.currentDate = currentDate;
	}

	@Override
	public Date getCurrentTime() {
		return currentDate;
	}

	@Override
	public void setDiagnosticData(DiagnosticData diagnosticData) {
		this.diagnosticDataJaxb = diagnosticData;
	}

	@Override
	public void setValidationPolicy(ValidationPolicy validationPolicy) {
		this.policy = validationPolicy;
	}

	@Override
	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
	}

	@Override
	public Reports execute() {
		// TODO Auto-generated method stub
		return null;
	}

}
