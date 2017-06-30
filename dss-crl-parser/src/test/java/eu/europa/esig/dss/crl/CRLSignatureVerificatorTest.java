package eu.europa.esig.dss.crl;

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.io.IOException;

import org.junit.Test;

public class CRLSignatureVerificatorTest {

	private CRLParser parser = new CRLParser();

	@Test
	public void test() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/belgium2.crl")) {

			CRLSignatureVerificator signatureVerificator = new CRLSignatureVerificator();

			parser.retrieveSignatureInfo(fis, signatureVerificator);

			assertEquals("1.2.840.113549.1.1.5", signatureVerificator.getSignatureAlgorithmOid().getId());
		}
	}

}
