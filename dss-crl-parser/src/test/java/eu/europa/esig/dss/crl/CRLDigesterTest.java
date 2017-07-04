package eu.europa.esig.dss.crl;

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;

public class CRLDigesterTest {

	private static final Logger LOG = LoggerFactory.getLogger(CRLDigesterTest.class);

	private CRLParser parser = new CRLParser();

	@Test
	public void hexCRL() throws IOException {
		try (InputStream is = new FileInputStream("src/test/resources/belgium2.crl")) {
			LOG.info(Utils.toHex(Utils.toByteArray(is)));
		}
	}

	@Test
	public void tbs() throws GeneralSecurityException {
		String hexTBS = "3057300D06092A864886F70D01010505003028310B3009060355040613024245311930170603550403131042656C6769756D20526F6F7420434132170D3133303731313131303030305A170D3134303133313131303030305A";
		byte[] bytes = Utils.fromHex(hexTBS);
		byte[] digest = getSHA1Digest().digest(bytes);
		String computedBase64 = Utils.toBase64(digest);
		String expectedBase64Digest = "9G6GVRFhXI2bEXfhM98aXOsamXk=";
		assertEquals(computedBase64, expectedBase64Digest);
	}

	@Test
	public void getDigest() throws IOException, GeneralSecurityException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/belgium2.crl");
				DigestInputStream dis = new DigestInputStream(fis, getSHA1Digest())) {

			CRLDigester digester = new CRLDigester(dis);

			parser.processDigest(dis, digester);

			byte[] digest = digester.getDigest();
			String computedBase64 = Utils.toBase64(digest);
			String expectedBase64Digest = "9G6GVRFhXI2bEXfhM98aXOsamXk=";
			assertEquals(computedBase64, expectedBase64Digest);
		}
	}

	@Test
	public void getDigestHuge() throws IOException, GeneralSecurityException {
		DigestInputStream dis = new DigestInputStream(new FileInputStream("src/test/resources/esteid2011.crl"), getSHA1Digest());
		CRLDigester digester = new CRLDigester(dis);

		parser.processDigest(dis, digester);

		byte[] digest = digester.getDigest();
		String computedBase64 = Utils.toBase64(digest);
		String expectedBase64Digest = "KzNkUHZHZ4sbnN44RAJLBlCVMZE=";
		assertEquals(computedBase64, expectedBase64Digest);
	}

	private MessageDigest getSHA1Digest() throws NoSuchAlgorithmException {
		return MessageDigest.getInstance("SHA1");
	}

}
