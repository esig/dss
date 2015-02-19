package eu.europa.ec.markt.dss.extension.asic.asics;

import eu.europa.ec.markt.dss.extension.asic.AbstractTestASiCwithXAdESExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class ASiCsExtensionWithXAdESBToLTTest extends AbstractTestASiCwithXAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.ASiC_S_BASELINE_B;
	}

	@Override
	protected SignatureLevel getOriginalUnderlyingSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.ASiC_S_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFinalUnderlyingSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LT;
	}
}
