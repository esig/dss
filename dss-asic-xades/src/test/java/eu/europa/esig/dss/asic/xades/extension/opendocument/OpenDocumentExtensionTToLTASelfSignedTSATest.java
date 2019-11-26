package eu.europa.esig.dss.asic.xades.extension.opendocument;

import java.io.File;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class OpenDocumentExtensionTToLTASelfSignedTSATest extends OpenDocumentExtensionTToLTATest {
	
	public OpenDocumentExtensionTToLTASelfSignedTSATest(File file) {
		super(file);
	}

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getSelfSignedTsa();
	}

}
