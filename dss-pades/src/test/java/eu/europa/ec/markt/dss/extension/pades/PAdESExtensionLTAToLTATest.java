package eu.europa.ec.markt.dss.extension.pades;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class PAdESExtensionLTAToLTATest extends AbstractTestPAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_LTA;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_LTA;
	}

}
