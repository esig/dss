package eu.europa.esig.dss.asic.xades.extension.asics;

public class ASiCsExtensionWithXAdESTToLTSelfSignedTest extends ASiCsExtensionWithXAdESTToLTTest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
