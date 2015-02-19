package eu.europa.ec.markt.dss.extension.xades;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class XAdESExtensionBToTTest extends AbstractTestXAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_T;
	}

}
