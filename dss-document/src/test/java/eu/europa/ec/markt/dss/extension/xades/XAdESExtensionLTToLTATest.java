package eu.europa.ec.markt.dss.extension.xades;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class XAdESExtensionLTToLTATest extends AbstractTestXAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		// TODO change XAdES_A to XAdES_BASELINE_LTA after DSS-631 Modify signature level detection XAdES / CAdES
		return SignatureLevel.XAdES_A;
	}

}
