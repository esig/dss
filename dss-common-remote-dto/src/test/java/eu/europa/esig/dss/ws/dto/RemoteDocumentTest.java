package eu.europa.esig.dss.ws.dto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class RemoteDocumentTest {

	@Test
	public void testDocNull() {
		RemoteDocument doc = new RemoteDocument();
		assertNotNull(doc.toString());
	}

	@Test
	public void testEquals() {
		RemoteDocument doc1 = new RemoteDocument(new byte[] { 1, 2, 3 }, "bla");
		RemoteDocument doc2 = new RemoteDocument(new byte[] { 1, 2, 3 }, "bla");
		assertTrue(doc1.equals(doc2));
		assertNotNull(doc1.toString());

		doc2.setDigestAlgorithm(DigestAlgorithm.SHA256);
		assertFalse(doc1.equals(doc2));
		assertNotNull(doc2.toString());
		doc2.setDigestAlgorithm(null);
		assertTrue(doc1.equals(doc2));

		doc2.setName("bli");
		assertFalse(doc1.equals(doc2));
		doc2.setName("bla");
		assertTrue(doc1.equals(doc2));

		doc2.setBytes(new byte[] { 0, 0, 0 });
		assertFalse(doc1.equals(doc2));
		doc2.setBytes(new byte[] { 1, 2, 3 });
		assertTrue(doc1.equals(doc2));
	}

}
