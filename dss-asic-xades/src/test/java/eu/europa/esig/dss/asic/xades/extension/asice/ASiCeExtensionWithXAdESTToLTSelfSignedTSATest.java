package eu.europa.esig.dss.asic.xades.extension.asice;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class ASiCeExtensionWithXAdESTToLTSelfSignedTSATest extends ASiCeExtensionWithXAdESTToLTTest {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
