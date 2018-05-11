package eu.europa.esig.dss.cookbook.example.sources;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.FileDocument;

public class DigestDocumentTest {

	@Test
	public void testDigestDocument() {

		// tag::demo[]

		// Firstly, we load a basic DSSDocument (FileDocument or InMemoryDocument)
		DSSDocument fileDocument = new FileDocument("src/main/resources/xml_example.xml");

		// After that, we create a DigestDocument
		DigestDocument digestDocument = new DigestDocument();
		digestDocument.setName(fileDocument.getName());

		// We add needed digest value(s). Eg : for a SHA-256 based signature
		digestDocument.addDigest(DigestAlgorithm.SHA256, fileDocument.getDigest(DigestAlgorithm.SHA256));

		// end::demo[]

		assertNotNull(digestDocument.getDigest(DigestAlgorithm.SHA256));

		try {
			digestDocument.getDigest(DigestAlgorithm.SHA512);
			fail("SHA-512 doesn't exist");
		} catch (DSSException e) {
			// normal behavior
		}

		try (InputStream is = digestDocument.openStream()) {
			fail("Cannot open a DigestDocument");
		} catch (DSSException | IOException e) {
			// normal behavior
		}

	}

}
