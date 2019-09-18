package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class CAdESExtensionTToLTSelfSignedTSATest extends CAdESExtensionTToLTTest {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}
	
}
