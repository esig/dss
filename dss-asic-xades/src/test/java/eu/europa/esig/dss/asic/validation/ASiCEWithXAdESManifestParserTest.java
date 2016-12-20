package eu.europa.esig.dss.asic.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.ManifestFile;

public class ASiCEWithXAdESManifestParserTest {

	@Test
	public void test() {
		DSSDocument signatureDoc = new InMemoryDocument("Hello".getBytes(), "test");
		DSSDocument manifestDoc = new FileDocument(new File("src/test/resources/manifest-sample.xml"));
		ASiCEWithXAdESManifestParser parser = new ASiCEWithXAdESManifestParser(signatureDoc, manifestDoc);

		ManifestFile description = parser.getDescription();
		assertNotNull(description);
		assertEquals("manifest-sample.xml", description.getFilename());
		assertEquals("test", description.getSignatureFilename());
		List<String> entries = description.getEntries();
		assertEquals(2, entries.size());
		assertTrue(entries.contains("test.txt"));
		assertTrue(entries.contains("test-data-file.bin"));
	}

}
