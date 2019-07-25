package eu.europa.esig.dss.xades.extension.prettyprint;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.extension.AbstractXAdESConsecutiveExtensionTest;

public class XAdESConsecutiveExtensionCToAPrettyPrintTest extends AbstractXAdESConsecutiveExtensionTest<XAdESSignatureParameters> {

	@Override
	protected DSSDocument getOriginalDocument() {
		return new FileDocument("src/test/resources/sample.xml");
	}

	@Override
	protected SignatureLevel getFirstSignSignatureLevel() {
		signatureParameters.setPrettyPrint(true);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_C);
		return SignatureLevel.XAdES_C;
	}

	@Override
	protected SignatureLevel getSecondSignSignatureLevel() {
		signatureParameters.setPrettyPrint(false);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_X);
		return SignatureLevel.XAdES_X;
	}

	@Override
	protected SignatureLevel getThirdSignSignatureLevel() {
		signatureParameters.setPrettyPrint(true);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_XL);
		return SignatureLevel.XAdES_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFourthSignSignatureLevel() {
		signatureParameters.setPrettyPrint(false);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_A);
		return SignatureLevel.XAdES_BASELINE_LTA;
	}	

}