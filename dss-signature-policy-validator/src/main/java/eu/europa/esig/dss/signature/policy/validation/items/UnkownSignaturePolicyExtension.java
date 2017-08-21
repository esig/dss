package eu.europa.esig.dss.signature.policy.validation.items;

public class UnkownSignaturePolicyExtension implements ItemValidator {
	
	private static final String UNKOWN_SIGN_POL_EXTENSION = "Unkown SignPolExtension: %s";
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
		return String.format(UNKOWN_SIGN_POL_EXTENSION, oid);
	}

}
