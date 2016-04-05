package eu.europa.esig.dss.xades.encoding;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang.ArrayUtils;
import org.apache.xml.security.algorithms.implementations.SignatureECDSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import eu.europa.esig.dss.EncryptionAlgorithm;
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
		assertTrue(ArrayUtils.isNotEmpty(convertToXmlDSig));

		byte[] xmlsec = SignatureECDSA.convertASN1toXMLDSIG(signatureValue);
		assertTrue(ArrayUtils.isEquals(convertToXmlDSig, xmlsec));
	}

	@Test
	public void testDSA() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();

		byte[] convertToXmlDSig = DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.DSA, signatureValue);
		assertTrue(ArrayUtils.isNotEmpty(convertToXmlDSig));
	}

	@Test
	public void testRSA() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] binary = s.sign();
		assertTrue(ArrayUtils.isEquals(binary, DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.RSA, binary)));
	}

	@Test
	public void testDSA2048() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
		gen.initialize(2048); // works with 4096 too but it takes lot of time
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();
		assertTrue(ArrayUtils.isNotEmpty(DSSSignatureUtils.convertToXmlDSig(EncryptionAlgorithm.DSA, signatureValue)));
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
		assertTrue(ArrayUtils.isNotEmpty(convertToXmlDSig));

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
		assertTrue(ArrayUtils.isNotEmpty(convertToXmlDSig));

		byte[] asn1xmlsec = SignatureECDSA.convertXMLDSIGtoASN1(convertToXmlDSig);

		Signature s2 = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
		s2.initVerify(pair.getPublic());
		s2.update(HELLO_WORLD.getBytes());
		assertTrue(s2.verify(asn1xmlsec));
	}

}
