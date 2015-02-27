package eu.europa.ec.markt.dss.extension.pades;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class PAdESExtensionBToTTest extends AbstractTestPAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_T;
	}

}
