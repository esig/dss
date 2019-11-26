package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class CAdESExtensionTToLTASelfSignedTSATest extends CAdESExtensionTToLTATest {
	
	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
