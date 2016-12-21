package eu.europa.esig.dss.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;

@Ignore("Only performance/support check. No need to be executed all the time")
public class SignatureTest {

	private CertificateService service = new CertificateService();

	private static FileDocument dssDocument;
	private static Map<DigestAlgorithm, ToBeSigned> toBeSignedsByDigest;

	@BeforeClass
	public static void init() throws Exception {
		File original = new File("target/large-file.bin");
		BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(original));
		byte[] data = new byte[1024];
		for (int i = 0; i < 1024 * 1024; i++) {
			out.write(data);
		}
		out.close();

		dssDocument = new FileDocument(original);
		toBeSignedsByDigest = new HashMap<DigestAlgorithm, ToBeSigned>();
	}

	/* RSA */
	@Test
	public void testRSASHA1() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.RSA_SHA1);
		signRSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testRSASHA224() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.RSA_SHA224);
		signRSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testRSASHA256() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);
		signRSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testRSASHA384() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.RSA_SHA384);
		signRSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testRSASHA512() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.RSA_SHA512);
		signRSAwithAllDigestAlgos(privateKeyEntry);
	}

	private void signRSAwithAllDigestAlgos(MockPrivateKeyEntry privateKeyEntry) {
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA1);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA224);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA256);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA384);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA512);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.RIPEMD160);
		// testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.MD2); not supported
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.MD5);
	}

	/* DSA */

	@Test
	public void testDSASHA1() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.DSA_SHA1);
		signDSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testDSASHA256() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.DSA_SHA256);
		signDSAwithAllDigestAlgos(privateKeyEntry);
	}

	private void signDSAwithAllDigestAlgos(MockPrivateKeyEntry privateKeyEntry) {
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA1);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA256);
	}

	/* ECDSA */

	@Test
	public void testECDSASHA1() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.ECDSA_SHA1);
		signECDSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testECDSASHA224() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.ECDSA_SHA224);
		signECDSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testECDSASHA256() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.ECDSA_SHA256);
		signECDSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testECDSASHA384() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.ECDSA_SHA384);
		signECDSAwithAllDigestAlgos(privateKeyEntry);
	}

	@Test
	public void testECDSASHA512() throws Exception {
		MockPrivateKeyEntry privateKeyEntry = service.generateCertificateChain(SignatureAlgorithm.ECDSA_SHA512);
		signECDSAwithAllDigestAlgos(privateKeyEntry);
	}

	private void signECDSAwithAllDigestAlgos(MockPrivateKeyEntry privateKeyEntry) {
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA1);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA224);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA256);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA384);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.SHA512);
		testWithDigestAlgo(privateKeyEntry, DigestAlgorithm.RIPEMD160);
	}

	private void testWithDigestAlgo(MockPrivateKeyEntry privateKeyEntry, DigestAlgorithm digest) {
		ToBeSigned dataToSign = getToBeSigned(digest);
		SignatureAlgorithm sigAlgo = SignatureAlgorithm.getAlgorithm(privateKeyEntry.getEncryptionAlgorithm(), digest);
		SignatureValue signatureValue = TestUtils.sign(sigAlgo, privateKeyEntry, dataToSign);
		assertNotNull(signatureValue);
		assertTrue(Utils.isArrayNotEmpty(signatureValue.getValue()));
		assertEquals(sigAlgo, signatureValue.getAlgorithm());
	}

	private ToBeSigned getToBeSigned(DigestAlgorithm digest) {
		if (toBeSignedsByDigest.containsKey(digest)) {
			return toBeSignedsByDigest.get(digest);
		} else {
			ToBeSigned dataToSign = new ToBeSigned(Utils.fromBase64(dssDocument.getDigest(digest)));
			toBeSignedsByDigest.put(digest, dataToSign);
			return dataToSign;
		}
	}

}
