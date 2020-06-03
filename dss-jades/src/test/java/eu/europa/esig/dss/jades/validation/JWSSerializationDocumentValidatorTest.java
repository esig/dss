package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.InMemoryDocument;

public class JWSSerializationDocumentValidatorTest {

	@Test
	public void test() {

		JWSSerializationDocumentValidator validator = new JWSSerializationDocumentValidator();

		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] {})));
		assertFalse(validator.isSupported(new InMemoryDocument("{".getBytes())));
		assertFalse(validator.isSupported(new InMemoryDocument("{}".getBytes())));
		assertFalse(validator.isSupported(new InMemoryDocument("{hello:\"world\"}".getBytes())));
		assertFalse(validator.isSupported(new InMemoryDocument("{\"hello\":\"world\"}".getBytes())));

		assertTrue(
				validator
						.isSupported(new InMemoryDocument("{\"payload\":\"AAA\",\"signatures\":[{\"protected\":\"BBB\",\"signature\":\"CCCC\"}]}".getBytes())));

	}
}
