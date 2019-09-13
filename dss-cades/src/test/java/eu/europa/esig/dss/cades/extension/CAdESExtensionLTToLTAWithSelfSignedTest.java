package eu.europa.esig.dss.cades.extension;

public class CAdESExtensionLTToLTAWithSelfSignedTest extends CAdESExtensionLTToLTATest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
