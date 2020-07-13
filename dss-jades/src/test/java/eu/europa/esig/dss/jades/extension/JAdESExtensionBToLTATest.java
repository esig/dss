package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.enumerations.SignatureLevel;

public class JAdESExtensionBToLTATest extends AbstractJAdESTestExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.JAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.JAdES_BASELINE_LTA;
	}

}
