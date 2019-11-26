package eu.europa.esig.dss.asic.xades.extension.asice;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class ASiCeExtensionWithXAdESBToLTASelfSignedTSATest extends ASiCeExtensionWithXAdESBToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
