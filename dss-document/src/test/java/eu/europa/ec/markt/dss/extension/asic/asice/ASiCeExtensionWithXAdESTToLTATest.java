package eu.europa.ec.markt.dss.extension.asic.asice;

import eu.europa.ec.markt.dss.extension.asic.AbstractTestASiCwithXAdESExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class ASiCeExtensionWithXAdESTToLTATest extends AbstractTestASiCwithXAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.ASiC_E_BASELINE_T;
	}

	@Override
	protected SignatureLevel getOriginalUnderlyingSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_T;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.ASiC_E_BASELINE_LTA;
	}

	@Override
	protected SignatureLevel getFinalUnderlyingSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LTA;
	}
}
