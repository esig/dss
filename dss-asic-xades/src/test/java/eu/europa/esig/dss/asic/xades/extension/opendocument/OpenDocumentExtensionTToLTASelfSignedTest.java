package eu.europa.esig.dss.asic.xades.extension.opendocument;

import java.io.File;

public class OpenDocumentExtensionTToLTASelfSignedTest extends OpenDocumentExtensionTToLTATest {
	
	public OpenDocumentExtensionTToLTASelfSignedTest(File file) {
		super(file);
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
