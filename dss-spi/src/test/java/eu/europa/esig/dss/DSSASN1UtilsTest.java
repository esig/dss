package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class DSSASN1UtilsTest {

	@Test
	public void getDigestSignaturePolicy() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/signature-policy-example.der");
		byte[] policyBytes = IOUtils.toByteArray(fis);
		IOUtils.closeQuietly(fis);

		byte[] signaturePolicyDigest = DSSASN1Utils.getAsn1SignaturePolicyDigest(DigestAlgorithm.SHA256, policyBytes);
		String hexSignaturePolicyDigest = Hex.encodeHexString(signaturePolicyDigest);

		assertEquals("fe71e01aedd99f444238602d4e98f47bbab405c58c0e3811b9511dcd58c3c983", hexSignaturePolicyDigest);
	}
}
