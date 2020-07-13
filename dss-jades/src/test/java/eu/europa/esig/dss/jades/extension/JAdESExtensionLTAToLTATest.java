package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.enumerations.SignatureLevel;

public class JAdESExtensionLTAToLTATest extends AbstractJAdESTestExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.JAdES_BASELINE_LTA;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.JAdES_BASELINE_LTA;
	}

}
