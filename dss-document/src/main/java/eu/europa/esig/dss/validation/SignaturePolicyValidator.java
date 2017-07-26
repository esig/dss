package eu.europa.esig.dss.validation;

public interface SignaturePolicyValidator {

	void setSignature(AdvancedSignature signature);

	boolean canValidate();

	void validate();

	// Validation results
	boolean isIdentified();

	boolean isStatus();

	boolean isAsn1Processable();

	boolean isDigestAlgorithmsEqual();

	String getProcessingErrors();

}