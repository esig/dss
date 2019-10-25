package eu.europa.esig.dss.asic.cades.extension.asics;

import eu.europa.esig.dss.asic.cades.extension.AbstractTestASiCwithCAdESExtension;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;

public class ASiCsExtensionWithCAdESTToLTASelfSignedTest extends AbstractTestASiCwithCAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_T;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LTA;
	}

	@Override
	protected ASiCContainerType getContainerType() {
		return ASiCContainerType.ASiC_S;
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
