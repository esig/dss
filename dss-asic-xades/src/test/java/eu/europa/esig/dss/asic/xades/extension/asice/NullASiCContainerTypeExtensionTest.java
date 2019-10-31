package eu.europa.esig.dss.asic.xades.extension.asice;

import eu.europa.esig.dss.asic.xades.extension.AbstractTestASiCwithXAdESExtension;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;

public class NullASiCContainerTypeExtensionTest extends AbstractTestASiCwithXAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_T;
	}

	@Override
	protected ASiCContainerType getContainerType() {
		return ASiCContainerType.ASiC_E;
	}

	@Override
	protected ASiCContainerType getFinalContainerType() {
		// No impact, the parameter is not used
		return null;
	}

}
