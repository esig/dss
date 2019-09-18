package eu.europa.esig.dss.pades.extension;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESExtensionTToLTASelfSignedTSA extends PAdESExtensionTToLTA {

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
