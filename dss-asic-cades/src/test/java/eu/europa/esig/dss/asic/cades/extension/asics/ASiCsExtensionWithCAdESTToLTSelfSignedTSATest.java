package eu.europa.esig.dss.asic.cades.extension.asics;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class ASiCsExtensionWithCAdESTToLTSelfSignedTSATest extends ASiCsExtensionWithCAdESTToLTTest {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
