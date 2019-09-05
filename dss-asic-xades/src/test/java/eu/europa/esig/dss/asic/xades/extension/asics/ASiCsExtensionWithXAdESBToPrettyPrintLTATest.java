package eu.europa.esig.dss.asic.xades.extension.asics;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;

public class ASiCsExtensionWithXAdESBToPrettyPrintLTATest extends ASiCsExtensionWithXAdESBToLTATest {
	
	@Override
	protected ASiCWithXAdESSignatureParameters getExtensionParameters() {
		ASiCWithXAdESSignatureParameters extensionParameters = new ASiCWithXAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		extensionParameters.aSiC().setContainerType(getContainerType());
		extensionParameters.setPrettyPrint(true);
		return extensionParameters;
	}
	
}
