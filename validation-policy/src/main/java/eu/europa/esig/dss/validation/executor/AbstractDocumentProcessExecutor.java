package eu.europa.esig.dss.validation.executor;

import java.util.Date;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.signature.ValidationLevel;

public abstract class AbstractDocumentProcessExecutor implements SignatureAndTimestampProcessExecutor {

	private Date currentTime = new Date();
	protected ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;
	protected boolean enableEtsiValidationReport = true;
	protected XmlDiagnosticData jaxbDiagnosticData;
	protected ValidationPolicy policy;

	@Override
	public void setCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}

	@Override
	public void setEnableEtsiValidationReport(boolean enableEtsiValidationReport) {
		this.enableEtsiValidationReport = enableEtsiValidationReport;
	}

	@Override
	public void setValidationPolicy(ValidationPolicy policy) {
		this.policy = policy;
	}

	@Override
	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

}
