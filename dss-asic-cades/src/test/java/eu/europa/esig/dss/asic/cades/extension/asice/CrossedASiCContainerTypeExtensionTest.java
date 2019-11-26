package eu.europa.esig.dss.asic.cades.extension.asice;

import eu.europa.esig.dss.asic.cades.extension.AbstractTestASiCwithCAdESExtension;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;

public class CrossedASiCContainerTypeExtensionTest extends AbstractTestASiCwithCAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_T;
	}

	@Override
	protected ASiCContainerType getContainerType() {
		return ASiCContainerType.ASiC_E;
	}

	@Override
	protected ASiCContainerType getFinalContainerType() {
		// No impact, the parameter is not used
		return ASiCContainerType.ASiC_S;
	}

}
