package eu.europa.esig.dss.asic.xades.extension.asics;

import eu.europa.esig.dss.asic.xades.extension.AbstractTestASiCwithXAdESExtension;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;

public class ASiCsExtensionWithXAdESTToLTASelfSignedTest extends AbstractTestASiCwithXAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_T;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LTA;
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
