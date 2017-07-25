package eu.europa.esig.dss.validation;

public interface SignaturePolicyValidator {
	public void setSignature(AdvancedSignature cadesSignature);
	
	public boolean canValidate();
	public void validate();

	// Validation results
	public boolean isIdentified();
	public boolean isStatus();
	public boolean isAsn1Processable();
	public boolean isDigestAlgorithmsEqual();
	public String getProcessingErrors();
}