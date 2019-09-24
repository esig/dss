package eu.europa.esig.dss.asic.xades.extension.asice;

public class ASiCeExtensionWithXAdESTToLTASelfSignedTest extends ASiCeExtensionWithXAdESTToLTATest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
