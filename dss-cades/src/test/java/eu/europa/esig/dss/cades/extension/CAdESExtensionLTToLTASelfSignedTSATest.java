package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class CAdESExtensionLTToLTASelfSignedTSATest extends CAdESExtensionLTToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
