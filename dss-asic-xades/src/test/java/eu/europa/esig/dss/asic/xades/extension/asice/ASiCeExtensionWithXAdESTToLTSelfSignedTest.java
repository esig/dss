package eu.europa.esig.dss.asic.xades.extension.asice;

public class ASiCeExtensionWithXAdESTToLTSelfSignedTest extends ASiCeExtensionWithXAdESTToLTTest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
