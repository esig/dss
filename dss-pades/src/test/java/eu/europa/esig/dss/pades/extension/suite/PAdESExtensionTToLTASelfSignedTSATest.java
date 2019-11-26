package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESExtensionTToLTASelfSignedTSATest extends PAdESExtensionTToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
