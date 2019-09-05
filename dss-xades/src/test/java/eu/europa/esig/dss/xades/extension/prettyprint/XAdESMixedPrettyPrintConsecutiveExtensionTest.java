package eu.europa.esig.dss.xades.extension.prettyprint;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.extension.AbstractXAdESConsecutiveExtension;

public class XAdESMixedPrettyPrintConsecutiveExtensionTest extends AbstractXAdESConsecutiveExtension<XAdESSignatureParameters> {

	@Override
	protected DSSDocument getOriginalDocument() {
		return new FileDocument("src/test/resources/sample.xml");
	}

	@Override
	protected SignatureLevel getFirstSignSignatureLevel() {
		signatureParameters.setPrettyPrint(true);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		return SignatureLevel.XAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getSecondSignSignatureLevel() {
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setPrettyPrint(false);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		return SignatureLevel.XAdES_BASELINE_T;
	}

	@Override
	protected SignatureLevel getThirdSignSignatureLevel() {
		signatureParameters.setPrettyPrint(true);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		return SignatureLevel.XAdES_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFourthSignSignatureLevel() {
		signatureParameters.setPrettyPrint(false);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		return SignatureLevel.XAdES_BASELINE_LTA;
	}	

}