package eu.europa.esig.dss.asic.xades.extension.asics;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class ASiCsExtensionWithXAdESLTToLTASelfSignedTSATest extends ASiCsExtensionWithXAdESLTToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
