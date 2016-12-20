package eu.europa.esig.dss.asic;

import org.junit.Test;

import eu.europa.esig.dss.SignatureLevel;

public class ASiCWithCAdESSignatureParametersTest {

	@Test(expected = IllegalArgumentException.class)
	public void testIllegal() {
		ASiCWithCAdESSignatureParameters params = new ASiCWithCAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
	}

}
