package eu.europa.esig.dss.web.model;

import javax.validation.constraints.AssertTrue;

import org.springframework.web.multipart.MultipartFile;

import eu.europa.esig.dss.validation.executor.ValidationLevel;

public class ValidationForm {

	private MultipartFile signedFile;

	private MultipartFile originalFile;

	private ValidationLevel validationLevel;

	private boolean defaultPolicy;

	private MultipartFile policyFile;

	public MultipartFile getSignedFile() {
		return signedFile;
	}

	public void setSignedFile(MultipartFile signedFile) {
		this.signedFile = signedFile;
	}

	public MultipartFile getOriginalFile() {
		return originalFile;
	}

	public void setOriginalFile(MultipartFile originalFile) {
		this.originalFile = originalFile;
	}

	public ValidationLevel getValidationLevel() {
		return validationLevel;
	}

	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}

	public boolean isDefaultPolicy() {
		return defaultPolicy;
	}

	public void setDefaultPolicy(boolean defaultPolicy) {
		this.defaultPolicy = defaultPolicy;
	}

	public MultipartFile getPolicyFile() {
		return policyFile;
	}

	public void setPolicyFile(MultipartFile policyFile) {
		this.policyFile = policyFile;
	}

	@AssertTrue(message = "{error.signed.file.mandatory}")
	public boolean isSignedFile() {
		return (signedFile != null) && (!signedFile.isEmpty());
	}

}
