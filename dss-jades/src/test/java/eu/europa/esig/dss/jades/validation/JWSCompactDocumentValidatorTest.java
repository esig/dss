package eu.europa.esig.dss.jades.validation;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class JWSCompactDocumentValidatorTest {

	@Test
	public void test() {
		
		JWSCompactDocumentValidator validator = new JWSCompactDocumentValidator();

		DSSDocument jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A".getBytes());
		assertTrue(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA".getBytes());
		assertTrue(validator.isSupported(jws));

		DSSDocument wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA".getBytes());
		assertFalse(validator.isSupported(wrong));
		wrong = new InMemoryDocument("<".getBytes());
		assertFalse(validator.isSupported(wrong));
		wrong = new InMemoryDocument("%PDF".getBytes());
		assertFalse(validator.isSupported(wrong));
		wrong = new InMemoryDocument(new byte[] {});
		assertFalse(validator.isSupported(wrong));
	}
	
}
