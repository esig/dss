package eu.europa.ec.markt.dss.extension.cades;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class CAdESExtensionLTToLTATest extends AbstractTestCAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LTA;
	}

}
