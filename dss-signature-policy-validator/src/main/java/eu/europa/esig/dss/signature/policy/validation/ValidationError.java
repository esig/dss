package eu.europa.esig.dss.signature.policy.validation;

public class ValidationError {
	private String target;
	private String description;
	
	public ValidationError(String target, String description) {
		super();
		this.target = target;
		this.description = description;
	}
	
	public String getTarget() {
		return target;
	}
	public String getDescription() {
		return description;
	}
}
