package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESExtensionLTToLTASelfSignedTSATest extends PAdESExtensionLTToLTATest {
	
	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
