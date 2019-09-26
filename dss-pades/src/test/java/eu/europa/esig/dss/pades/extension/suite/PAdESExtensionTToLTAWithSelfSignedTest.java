package eu.europa.esig.dss.pades.extension.suite;

public class PAdESExtensionTToLTAWithSelfSignedTest extends PAdESExtensionTToLTATest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
