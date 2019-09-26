package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESExtensionBToLTASelfSignedTSATest extends PAdESExtensionBToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
