package eu.europa.esig.dss.asic;

import org.junit.Test;

import eu.europa.esig.dss.SignatureLevel;

public class ASiCWithXAdESSignatureParametersTest {

	@Test(expected = IllegalArgumentException.class)
	public void test() {
		ASiCWithXAdESSignatureParameters params = new ASiCWithXAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
	}

}
