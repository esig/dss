package eu.europa.esig.dss.xades.extension;

public class XAdESExtensionLTtoLTAWithSelfSignedTest extends XAdESExtensionLTToLTATest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
