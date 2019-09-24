package eu.europa.esig.dss.pades.extension;

public class PAdESExtensionTToLTAWithSelfSigned extends PAdESExtensionTToLTA {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
