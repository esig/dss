package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.enumerations.SignatureLevel;

public class CAdESExtensionLTToLTTest extends AbstractCAdESTestExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LT;
	}

}
