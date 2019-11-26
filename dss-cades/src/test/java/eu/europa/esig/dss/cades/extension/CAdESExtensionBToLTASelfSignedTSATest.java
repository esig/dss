package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class CAdESExtensionBToLTASelfSignedTSATest extends CAdESExtensionBToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
