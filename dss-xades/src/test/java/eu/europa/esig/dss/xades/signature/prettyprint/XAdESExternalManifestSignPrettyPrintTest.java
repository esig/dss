package eu.europa.esig.dss.xades.signature.prettyprint;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESExternalManifestLevelBTest;

public class XAdESExternalManifestSignPrettyPrintTest extends XAdESExternalManifestLevelBTest {

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setPrettyPrint(true);
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return new FileDocument("src/test/resources/manifest-oneline.xml");
	}

}
