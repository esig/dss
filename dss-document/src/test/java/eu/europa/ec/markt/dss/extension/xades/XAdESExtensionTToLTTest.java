package eu.europa.ec.markt.dss.extension.xades;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class XAdESExtensionTToLTTest extends AbstractTestXAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_T;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LT;
	}

}
