package eu.europa.esig.dss.asic.xades.extension.opendocument;

import java.io.File;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class OpenDocumentExtensionBToLTASelfSignedTSATest extends OpenDocumentExtensionBToLTATest {
	
	public OpenDocumentExtensionBToLTASelfSignedTSATest(File file) {
		super(file);
	}

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getSelfSignedTsa();
	}

}
