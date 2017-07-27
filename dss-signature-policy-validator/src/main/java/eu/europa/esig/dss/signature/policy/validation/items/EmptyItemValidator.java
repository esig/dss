package eu.europa.esig.dss.signature.policy.validation.items;

public class EmptyItemValidator implements ItemValidator {
	public boolean validate() {
		return true;
	}

	@Override
	public String getErrorDetail() {
		return "";
	}
}