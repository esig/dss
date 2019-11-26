package eu.europa.esig.dss.pades.extension.suite;

public class PAdESExtensionTToLTWithSelfSignedTest extends PAdESExtensionTToLTTest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
