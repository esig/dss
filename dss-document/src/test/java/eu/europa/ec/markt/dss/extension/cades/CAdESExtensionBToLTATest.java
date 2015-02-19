package eu.europa.ec.markt.dss.extension.cades;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class CAdESExtensionBToLTATest extends AbstractTestCAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LTA;
	}

}
