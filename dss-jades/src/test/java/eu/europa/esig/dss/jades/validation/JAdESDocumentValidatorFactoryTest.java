package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.DocumentValidator;

public class JAdESDocumentValidatorFactoryTest {

	private JAdESDocumentValidatorFactory factory = new JAdESDocumentValidatorFactory();

	@Test
	public void compact() {
		DSSDocument jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A".getBytes());
		assertTrue(factory.isSupported(jws));

		DocumentValidator documentValidator = factory.create(jws);
		assertNotNull(documentValidator);
		assertTrue(documentValidator instanceof JWSCompactDocumentValidator);
	}

	@Test
	public void serialization() {
		DSSDocument jws = new InMemoryDocument("{\"hello\":\"world\"}".getBytes());
		assertTrue(factory.isSupported(jws));

		DocumentValidator documentValidator = factory.create(jws);
		assertNotNull(documentValidator);
		assertTrue(documentValidator instanceof JWSSerializationDocumentValidator);
	}

	@Test
	public void unsupported() {
		DSSDocument doc = new InMemoryDocument("AAA".getBytes());
		assertFalse(factory.isSupported(doc));

		assertThrows(IllegalArgumentException.class, () -> factory.create(doc));
	}

}
