package eu.europa.esig.dss.signature.policy.validation.items;

public interface ItemValidator {
	public boolean validate();
	public String getErrorDetail();
}
