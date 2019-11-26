package eu.europa.esig.dss.asic.cades.extension.asice;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class ASiCeExtensionWithCAdESBToLTASelfSignedTSATest extends ASiCeExtensionWithCAdESBToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
