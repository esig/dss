package eu.europa.esig.dss.xades.encoding;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.apache.xml.security.algorithms.implementations.SignatureECDSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.signature.DSSSignatureUtils;

public class EncodingXMLTest {

	private static final String HELLO_WORLD = "Hello World";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void test() throws Exception {
		String test = "MEQCIEJNA0AElH/vEH9xLxvqrwCqh+yUh9ACL2vU/2eObRbTAiAxTLSWSioJrfSwPkKcypf+KCHvMGdwZbRWQHnZN2sDnQ==";
		byte[] signatureValue = DatatypeConverter.parseBase64Binary(test);

		byte[] convertToXmlDSig = DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.ECDSA, signatureValue);
		assertTrue(Utils.isArrayNotEmpty(convertToXmlDSig));

		byte[] xmlsec = SignatureECDSA.convertASN1toXMLDSIG(signatureValue);
		assertTrue(Arrays.equals(convertToXmlDSig, xmlsec));
	}

	// Annotation for error_probe
	@SuppressWarnings("InsecureCryptoUsage")
	@Test
	public void testDSA() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();

		byte[] convertToXmlDSig = DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.DSA, signatureValue);
		assertTrue(Utils.isArrayNotEmpty(convertToXmlDSig));
	}

	@Test
	public void testRSA() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] binary = s.sign();
		assertTrue(Arrays.equals(binary, DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.RSA, binary)));
	}

	// Annotation for error_probe
	@SuppressWarnings("InsecureCryptoUsage")
	@Test
	public void testDSA2048() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
		gen.initialize(2048); // works with 4096 too but it takes lot of time
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();
		assertTrue(Utils.isArrayNotEmpty(DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.DSA, signatureValue)));
	}

	@Test
	public void testECDSA() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();

		byte[] convertToXmlDSig = DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.ECDSA, signatureValue);
		assertTrue(Utils.isArrayNotEmpty(convertToXmlDSig));

		byte[] asn1xmlsec = SignatureECDSA.convertXMLDSIGtoASN1(convertToXmlDSig);

		Signature s2 = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
		s2.initVerify(pair.getPublic());
		s2.update(HELLO_WORLD.getBytes());
		assertTrue(s2.verify(asn1xmlsec));
	}

	@Test
	public void testECDSA192() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
		gen.initialize(192);
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();

		byte[] convertToXmlDSig = DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.ECDSA, signatureValue);
		assertTrue(Utils.isArrayNotEmpty(convertToXmlDSig));

		byte[] asn1xmlsec = SignatureECDSA.convertXMLDSIGtoASN1(convertToXmlDSig);

		Signature s2 = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
		s2.initVerify(pair.getPublic());
		s2.update(HELLO_WORLD.getBytes());
		assertTrue(s2.verify(asn1xmlsec));
	}

	@Test
	public void testECDSA_CVC_ConcatenatedSignature() throws Exception {
		assertCvcSignatureValid(
				"2B9099C9885DDB5BFDA2E9634905B9A63E7E3A6EC87BDC0A89014716B23F00B0AD787FC8D0DCF28F007E7DEC097F30DA892BE2AC61D90997DCDF05740E4D5B0C");
		assertCvcSignatureValid(
				"947b79069e6a1e3316ec15d696649a4b67c6c188df9bc05458f3b0b94907f3fb52522d4cae24a75735969cff556b1476a5ccbe37ca65a928782c14f299f3b2d3");
		assertCvcSignatureValid(
				"28a1583e58e93a661322f776618d83b023bdc52b2e909cf9d53030b9260ed667b588fd39eeee5b1b55523a7e71cb4187d8b1bbf56c1581fc845863157d279cf5");
		assertCvcSignatureValid(
				"dd8fc5414eda2920d347f3d3f9f604fcf09392a8ce3807f6f87d006cf8ed1959075af8abbb030e6990da52fe49c93486a4b98bb2e18e0f84095175eddabfbb96");
		assertCvcSignatureValid(
				"1daf408ead014bba9f243849ece308b31f898e1ce97b54a78b3c15eb103fa8a1c87bdd97fdfc4cb56a7e1e5650dee2ebfff0b56d5a2ca0338e6ed59689e27ae1323f32b0f93b41987a816c93c00462c68c609692084dbced7308a8a66f0365ee5b7b272273e8abd4ddd4a49d2fd67964bc8c757114791446b9716f3b7f551608");
		assertCvcSignatureValid(
				"0d2fc9f18d816e9054af943c392dd46f09da71521de9bd98d765e170f12eb086d3d0f9754105001ed2e703d7290ac967642bc70bdd7a96b5c2b8e3d4b503b80e");
		assertCvcSignatureValid(
				"065a15bd4fec67a2a302d9d3ec679cb8f298f9d6a1d855d3dbf39b3f2fa7ea461e437d9542c4a9527afe5e78c1412937f0dbb05a78380cfb2e1bf6eff944581a");
	}

	private void assertCvcSignatureValid(String cvcSignatureInHex) {
		byte[] signatureValue = DatatypeConverter.parseHexBinary(cvcSignatureInHex);
		byte[] xmlDSigValue = DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.ECDSA, signatureValue);
		assertThat(signatureValue, equalTo(xmlDSigValue));
	}
}
