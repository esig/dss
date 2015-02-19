package eu.europa.ec.markt.dss.extension.xades;

import eu.europa.ec.markt.dss.signature.SignatureLevel;

public class XAdESExtensionBToLTATest extends AbstractTestXAdESExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		// TODO change XAdES_A to XAdES_BASELINE_LTA after DSS-631 Modify signature level detection XAdES / CAdES
		return SignatureLevel.XAdES_A;
	}

}
