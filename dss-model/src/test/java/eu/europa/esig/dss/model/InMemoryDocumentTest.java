package eu.europa.esig.dss.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class InMemoryDocumentTest {

	@Test
	public void test() {
		InMemoryDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/AdobeCA.p7c"));
		assertNotNull(doc);
		assertNull(doc.getAbsolutePath());
		assertNull(doc.getMimeType());
		assertNull(doc.getName());
		assertNotNull(doc.getBytes());
		assertNotNull(doc.getDigest(DigestAlgorithm.SHA256));
	}

	@Test
	public void testSetter() {
		InMemoryDocument doc = new InMemoryDocument();
		assertNotNull(doc);
		assertNull(doc.getAbsolutePath());
		assertNull(doc.getMimeType());
		assertNull(doc.getName());
		assertNull(doc.getBytes());
		NullPointerException exception = assertThrows(NullPointerException.class, () -> doc.getDigest(DigestAlgorithm.SHA256));
		assertEquals("Bytes are null", exception.getMessage());

		byte[] bytes = new byte[] { 1, 2, 3 };
		doc.setBytes(bytes);
		doc.setName("doc.txt");
		doc.setMimeType(MimeType.TEXT);
		assertNotNull(doc.getMimeType());
		assertNotNull(doc.getName());
		assertNotNull(doc.getBytes());
		assertNotNull(doc.getDigest(DigestAlgorithm.SHA256));
	}

	@Test
	public void testWithName() {
		InMemoryDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/AdobeCA.p7c"), "AdobeCA.p7c");
		assertNotNull(doc);
		assertNull(doc.getAbsolutePath());
		assertEquals(MimeType.BINARY, doc.getMimeType());
		assertNotNull(doc.getName());
		assertNotNull(doc.getBytes());
		assertNotNull(doc.getDigest(DigestAlgorithm.SHA256));
	}

	@Test
	public void testBytes() {
		byte[] bytes = new byte[] { 1, 2, 3 };

		InMemoryDocument doc = new InMemoryDocument(bytes, "doc.txt");
		assertNotNull(doc);
		assertEquals(MimeType.TEXT, doc.getMimeType());
		assertNotNull(doc.getName());
		assertNotNull(doc.getBytes());
		assertNotNull(doc.getDigest(DigestAlgorithm.SHA256));
		assertNull(doc.getAbsolutePath());
	}

	@Test
	public void testFileNotFound() {
		NullPointerException exception = assertThrows(NullPointerException.class, () -> new InMemoryDocument(getClass().getResourceAsStream("/AdobeCAAA.p7c")));
		assertEquals("The InputStream is null", exception.getMessage());
	}

	@Test
	public void testNullInputStream() {
		NullPointerException exception = assertThrows(NullPointerException.class, () -> new InMemoryDocument((InputStream) null));
		assertEquals("The InputStream is null", exception.getMessage());
	}

	@Test
	public void testNullBytes() {
		NullPointerException exception = assertThrows(NullPointerException.class, () -> new InMemoryDocument((byte[]) null));
		assertEquals("Bytes cannot be null", exception.getMessage());
	}

}
