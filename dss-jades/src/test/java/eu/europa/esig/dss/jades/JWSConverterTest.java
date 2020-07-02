package eu.europa.esig.dss.jades;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.jades.validation.JWSSerializationDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;

public class JWSConverterTest {

	@Test
	public void testNotJSONCompact() {
		InMemoryDocument helloDoc = new InMemoryDocument("Hello".getBytes());
		DSSException exception = assertThrows(DSSException.class, () -> JWSConverter.fromJWSCompactToJSONFlattenedSerialization(helloDoc));
		assertEquals("Unable to instantiate a compact JWS", exception.getMessage());
		exception = assertThrows(DSSException.class, () -> JWSConverter.fromJWSCompactToJSONSerialization(helloDoc));
		assertEquals("Unable to instantiate a compact JWS", exception.getMessage());
	}

	@Test
	public void test3Parts() {
		JWSSerializationDocumentValidator validator = new JWSSerializationDocumentValidator();

		DSSDocument jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A".getBytes());
		DSSDocument converted = JWSConverter.fromJWSCompactToJSONFlattenedSerialization(jws);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());
		assertTrue(validator.isSupported(converted));

		converted = JWSConverter.fromJWSCompactToJSONSerialization(jws);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());
		assertTrue(validator.isSupported(converted));

	}

	@Test
	public void test2Parts() {
		JWSSerializationDocumentValidator validator = new JWSSerializationDocumentValidator();

		DSSDocument jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA".getBytes());
		DSSDocument converted = JWSConverter.fromJWSCompactToJSONFlattenedSerialization(jws);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());
		assertTrue(validator.isSupported(converted));

		converted = JWSConverter.fromJWSCompactToJSONSerialization(jws);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());
		assertTrue(validator.isSupported(converted));

	}

}
