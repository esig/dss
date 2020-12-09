package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.validation.ReferenceValidation;

import java.util.ArrayList;
import java.util.List;

/**
 * The JAdES reference validation result
 */
public class JAdESReferenceValidation extends ReferenceValidation {
	
	private static final long serialVersionUID = 2819574054512130987L;

	/** List of errors occurred during the reference validation */
	private List<String> errorMessages = new ArrayList<>();

	/**
	 * Gets error messages occurred during the reference validation
	 *
	 * @return a list of {@link String} messages
	 */
	public List<String> getErrorMessages() {
		return errorMessages;
	}

	/**
	 * Sets error messages occurred during the reference validation
	 *
	 * @param errorMessages a list of {@link String} messages
	 */
	public void setErrorMessages(List<String> errorMessages) {
		this.errorMessages = errorMessages;
	}

}
