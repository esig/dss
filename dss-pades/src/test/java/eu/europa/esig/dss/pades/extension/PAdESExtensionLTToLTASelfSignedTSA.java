package eu.europa.esig.dss.pades.extension;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESExtensionLTToLTASelfSignedTSA extends PAdESExtensionLTToLTA {
	
	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
