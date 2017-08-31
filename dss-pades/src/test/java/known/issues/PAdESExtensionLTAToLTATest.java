package known.issues;

import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.pades.extension.AbstractTestPAdESExtension;

public class PAdESExtensionLTAToLTATest extends AbstractTestPAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_LTA;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_LTA;
	}

}
