package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

public class FileDocumentTest {

	@Test(expected = NullPointerException.class)
	public void testNull() {
		new FileDocument((String) null);
	}

	@Test(expected = NullPointerException.class)
	public void testNull2() {
		new FileDocument((File) null);
	}

	@Test
	public void testFile() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/AdobeCA.p7c");
		assertNotNull(doc);
		assertTrue(doc.exists());
		assertEquals("AdobeCA.p7c", doc.getName());
		assertEquals(MimeType.BINARY, doc.getMimeType());
		assertEquals("xF8SpcLlrd4Bhl1moh4Ciz+Rq/PImaChEl/tyGTZyPM=", doc.getDigest(DigestAlgorithm.SHA256));
		String path = "target/testFileDocument";
		doc.save(path);

		File file = new File(path);
		assertTrue(file.exists());
	}
}
