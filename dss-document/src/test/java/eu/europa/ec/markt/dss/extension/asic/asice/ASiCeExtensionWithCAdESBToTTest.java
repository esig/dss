package eu.europa.ec.markt.dss.extension.asic.asice;

import eu.europa.ec.markt.dss.extension.asic.AbstractTestASiCwithCAdESExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class ASiCeExtensionWithCAdESBToTTest extends AbstractTestASiCwithCAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.ASiC_E_BASELINE_B;
	}

	@Override
	protected SignatureLevel getOriginalUnderlyingSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.ASiC_E_BASELINE_T;
	}

	@Override
	protected SignatureLevel getFinalUnderlyingSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_T;
	}
}
