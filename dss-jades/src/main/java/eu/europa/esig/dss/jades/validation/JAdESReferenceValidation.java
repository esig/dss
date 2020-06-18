package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.validation.ReferenceValidation;

public class JAdESReferenceValidation extends ReferenceValidation {
	
	private static final long serialVersionUID = 2819574054512130987L;
	
	private List<String> errorMessages = new ArrayList<>();
	
	public void addErrorMessage(String errorMessage) {
		errorMessages.add(errorMessage);
	}

	public List<String> getErrorMessages() {
		return errorMessages;
	}

}
