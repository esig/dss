package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

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
	
	@Test
	public void unsupportedAlgorithmTest() {
		assertThrows(IllegalArgumentException.class, () -> {
			assertNull(EncryptionAlgorithmParser.parse("bla"));
		});
	}

}
