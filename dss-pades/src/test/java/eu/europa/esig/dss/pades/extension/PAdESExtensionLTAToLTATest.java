package eu.europa.esig.dss.pades.extension;

import eu.europa.esig.dss.SignatureLevel;

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
