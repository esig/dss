package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Constructor;

import org.junit.Test;

import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;

public class XMLDocumentValidatorTest {

	private static XMLDocumentValidator VALIDATOR;

	static {
		try {
			Constructor<XMLDocumentValidator> defaultAndPrivateConstructor = XMLDocumentValidator.class.getDeclaredConstructor();
			defaultAndPrivateConstructor.setAccessible(true);
			VALIDATOR = defaultAndPrivateConstructor.newInstance();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void isSupported() {
		byte[] wrongBytes = new byte[] { 1, 2 };
		assertFalse(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes)));
		assertFalse(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes, "test", MimeType.PDF)));
		assertFalse(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes, "test")));

		assertTrue(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes, "test", MimeType.XML)));
		assertTrue(VALIDATOR.isSupported(new InMemoryDocument(wrongBytes, "test.xml")));
		assertTrue(VALIDATOR.isSupported(new InMemoryDocument(new byte[] { '<', '?', 'x', 'm', 'l' })));
	}

}
