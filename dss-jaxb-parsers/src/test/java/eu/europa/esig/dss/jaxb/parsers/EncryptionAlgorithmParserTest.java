package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;

public class EncryptionAlgorithmParserTest {

	@Test
	public void testEnum() {
		for (EncryptionAlgorithm ea : EncryptionAlgorithm.values()) {
			String string = EncryptionAlgorithmParser.print(ea);
			assertNotNull(string);
			EncryptionAlgorithm parse = EncryptionAlgorithmParser.parse(string);
			assertEquals(ea, parse);
		}
	}

	@Test
	public void parseAlgos() {
		assertNotNull(EncryptionAlgorithmParser.parse("RSA"));
		assertNotNull(EncryptionAlgorithmParser.parse("DSA"));
		assertNotNull(EncryptionAlgorithmParser.parse("EC"));
		assertNotNull(EncryptionAlgorithmParser.parse("ECC"));
		assertNotNull(EncryptionAlgorithmParser.parse("PLAIN-ECDSA"));
		assertNotNull(EncryptionAlgorithmParser.parse("PLAIN_ECDSA"));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void unsupportedAlgorithmTest() {
		EncryptionAlgorithmParser.parse("bla");
	}

}
