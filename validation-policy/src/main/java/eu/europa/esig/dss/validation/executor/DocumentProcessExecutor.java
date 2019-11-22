package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.validation.executor.signature.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;

public interface DocumentProcessExecutor extends ProcessExecutor<Reports> {

	/**
	 * This method allows to set the validation level that is used during the
	 * validation process execution.
	 *
	 * @param validationLevel
	 *            the validation level.
	 */
	void setValidationLevel(ValidationLevel validationLevel);
	
	/**
	 * Specifies if the ETSI Validation Report must be created
	 * 
	 * @param enableEtsiValidationReport
	 */
	void setEnableEtsiValidationReport(boolean enableEtsiValidationReport);

}
