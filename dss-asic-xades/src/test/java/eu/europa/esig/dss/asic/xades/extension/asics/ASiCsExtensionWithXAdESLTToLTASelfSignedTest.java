package eu.europa.esig.dss.asic.xades.extension.asics;

public class ASiCsExtensionWithXAdESLTToLTASelfSignedTest extends ASiCsExtensionWithXAdESLTToLTATest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
