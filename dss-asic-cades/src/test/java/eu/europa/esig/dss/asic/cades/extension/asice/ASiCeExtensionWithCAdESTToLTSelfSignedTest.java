package eu.europa.esig.dss.asic.cades.extension.asice;

import eu.europa.esig.dss.asic.cades.extension.AbstractTestASiCwithCAdESExtension;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;

public class ASiCeExtensionWithCAdESTToLTSelfSignedTest extends AbstractTestASiCwithCAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_T;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LT;
	}

	@Override
	protected ASiCContainerType getContainerType() {
		return ASiCContainerType.ASiC_E;
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
