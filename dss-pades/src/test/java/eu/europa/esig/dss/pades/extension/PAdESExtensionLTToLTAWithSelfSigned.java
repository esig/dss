package eu.europa.esig.dss.pades.extension;

public class PAdESExtensionLTToLTAWithSelfSigned extends PAdESExtensionLTToLTA {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
