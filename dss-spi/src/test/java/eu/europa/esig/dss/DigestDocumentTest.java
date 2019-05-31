package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Test;

public class DigestDocumentTest {

	@Test
	public void test() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument();
		doc.addDigest(DigestAlgorithm.SHA1, base64EncodeDigest);
		assertEquals(base64EncodeDigest, doc.getDigest(DigestAlgorithm.SHA1));
	}

	@Test(expected = DSSException.class)
	public void testUnknownDigest() {
		String base64EncodeDigest = "aaa";
		DigestDocument doc = new DigestDocument();
		doc.addDigest(DigestAlgorithm.SHA1, base64EncodeDigest);
		doc.getDigest(DigestAlgorithm.SHA256);
	}

	@Test(expected = DSSException.class)
	public void testOpenStream() {
		DigestDocument doc = new DigestDocument();
		doc.openStream();
	}

	@Test(expected = DSSException.class)
	public void testSave() throws IOException {
		DigestDocument doc = new DigestDocument();
		doc.save("target/test");
	}

}
