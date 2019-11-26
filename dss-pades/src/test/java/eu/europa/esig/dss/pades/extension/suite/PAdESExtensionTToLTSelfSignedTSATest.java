package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESExtensionTToLTSelfSignedTSATest extends PAdESExtensionTToLTTest {
	
	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
