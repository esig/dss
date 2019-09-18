package eu.europa.esig.dss.pades.extension;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESExtensionTToLTSelfSignedTSA extends PAdESExtensionTToLT {
	
	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
