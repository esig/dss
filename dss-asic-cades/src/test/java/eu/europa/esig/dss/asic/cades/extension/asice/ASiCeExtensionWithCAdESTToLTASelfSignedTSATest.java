package eu.europa.esig.dss.asic.cades.extension.asice;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class ASiCeExtensionWithCAdESTToLTASelfSignedTSATest extends ASiCeExtensionWithCAdESTToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
