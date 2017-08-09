package eu.europa.esig.dss.crl;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;

public class CRLDigesterTest {

	private CRLParser parser = new CRLParser();

	@Test
	public void getDigest() throws IOException, GeneralSecurityException {
		try (InputStream is = CRLDigesterTest.class.getResourceAsStream("/belgium2.crl"); DigestInputStream dis = new DigestInputStream(is, getSHA1Digest())) {

			parser.processDigest(dis);

			byte[] digest = dis.getMessageDigest().digest();
			String computedBase64 = Utils.toBase64(digest);
			String expectedBase64Digest = "9G6GVRFhXI2bEXfhM98aXOsamXk=";
			assertEquals(computedBase64, expectedBase64Digest);
		}
	}

	private MessageDigest getSHA1Digest() throws NoSuchAlgorithmException {
		return MessageDigest.getInstance("SHA1");
	}

}
