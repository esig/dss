package eu.europa.esig.dss.pades.extension;

public class PAdESExtensionTToLTWithSelfSigned extends PAdESExtensionTToLT {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
