package eu.europa.esig.dss.signature.policy.validation.items;

public class UnkownSignaturePolicyExtension implements ItemValidator {
	
	private static final String UNKNOWN_SIGN_POL_EXTENSION = "Unknown SignPolExtension: %s";
	private String oid;
	
	public UnkownSignaturePolicyExtension(String oid) {
		this.oid = oid;
	}

	@Override
	public boolean validate() {
		return false;
	}

	@Override
	public String getErrorDetail() {
		return String.format(UNKNOWN_SIGN_POL_EXTENSION, oid);
	}

}
