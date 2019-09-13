package eu.europa.esig.dss.cades.extension;

public class CAdESExtensionTToLTAWithSelfSignedTest extends CAdESExtensionTToLTATest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
