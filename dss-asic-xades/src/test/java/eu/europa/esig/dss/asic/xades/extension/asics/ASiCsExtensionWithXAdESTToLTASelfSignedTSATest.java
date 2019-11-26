package eu.europa.esig.dss.asic.xades.extension.asics;

import eu.europa.esig.dss.asic.xades.extension.asice.ASiCeExtensionWithXAdESTToLTATest;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class ASiCsExtensionWithXAdESTToLTASelfSignedTSATest extends ASiCeExtensionWithXAdESTToLTATest {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
