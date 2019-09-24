package eu.europa.esig.dss.cades.extension;

public class CAdESExtensionTToLTWithSelfSignedTest extends CAdESExtensionTToLTTest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
