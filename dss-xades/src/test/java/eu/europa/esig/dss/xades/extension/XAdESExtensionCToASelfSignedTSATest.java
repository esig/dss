package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class XAdESExtensionCToASelfSignedTSATest extends XAdESExtensionCToATest {

    @Override
    protected TSPSource getUsedTSPSourceAtExtensionTime() {
        return getSelfSignedTsa();
    }

}
