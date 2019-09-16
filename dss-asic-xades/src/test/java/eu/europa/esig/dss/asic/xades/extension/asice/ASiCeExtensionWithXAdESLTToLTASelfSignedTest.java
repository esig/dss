package eu.europa.esig.dss.asic.xades.extension.asice;

public class ASiCeExtensionWithXAdESLTToLTASelfSignedTest extends ASiCeExtensionWithXAdESLTToLTATest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
