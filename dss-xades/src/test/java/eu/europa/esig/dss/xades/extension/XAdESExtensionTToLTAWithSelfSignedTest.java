package eu.europa.esig.dss.xades.extension;

public class XAdESExtensionTToLTAWithSelfSignedTest extends XAdESExtensionTToLTATest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
