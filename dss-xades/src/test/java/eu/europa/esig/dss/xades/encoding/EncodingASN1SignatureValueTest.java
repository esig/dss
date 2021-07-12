/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.encoding;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import org.apache.xml.security.algorithms.implementations.SignatureECDSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EncodingASN1SignatureValueTest {

	private static final String HELLO_WORLD = "Hello World";

	@Test
	public void test() throws Exception {
		String test = "MEQCIEJNA0AElH/vEH9xLxvqrwCqh+yUh9ACL2vU/2eObRbTAiAxTLSWSioJrfSwPkKcypf+KCHvMGdwZbRWQHnZN2sDnQ==";
		byte[] signatureValue = DatatypeConverter.parseBase64Binary(test);

		byte[] convertToXmlDSig = DSSASN1Utils.ensurePlainSignatureValue(EncryptionAlgorithm.ECDSA, signatureValue);
		assertTrue(Utils.isArrayNotEmpty(convertToXmlDSig));

		byte[] xmlsec = SignatureECDSA.convertASN1toXMLDSIG(signatureValue);
        assertArrayEquals(convertToXmlDSig, xmlsec);
	}

	@Test
	public void testDSA() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withDSA");
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();

		byte[] convertToXmlDSig = DSSASN1Utils.ensurePlainSignatureValue(EncryptionAlgorithm.DSA, signatureValue);
		assertTrue(Utils.isArrayNotEmpty(convertToXmlDSig));
	}

	@Test
	public void testRSA() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withRSA");
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] binary = s.sign();
		assertArrayEquals(binary, DSSASN1Utils.ensurePlainSignatureValue(EncryptionAlgorithm.RSA, binary));
	}

	@Test
	public void testDSA2048() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
		gen.initialize(2048); // works with 4096 too but it takes lot of time
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withDSA");
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();
		assertTrue(Utils.isArrayNotEmpty(DSSASN1Utils.ensurePlainSignatureValue(EncryptionAlgorithm.DSA, signatureValue)));
	}

	@Test
	public void testECDSA() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA");
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withECDSA");
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();

		byte[] convertToXmlDSig = DSSASN1Utils.ensurePlainSignatureValue(EncryptionAlgorithm.ECDSA, signatureValue);
		assertTrue(Utils.isArrayNotEmpty(convertToXmlDSig));

		byte[] asn1xmlsec = SignatureECDSA.convertXMLDSIGtoASN1(convertToXmlDSig);

		Signature s2 = Signature.getInstance("SHA256withECDSA");
		s2.initVerify(pair.getPublic());
		s2.update(HELLO_WORLD.getBytes());
		assertTrue(s2.verify(asn1xmlsec));
	}

	@Test
	public void testECDSA192() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA");
		gen.initialize(192);
		KeyPair pair = gen.generateKeyPair();

		Signature s = Signature.getInstance("SHA256withECDSA");
		s.initSign(pair.getPrivate());
		s.update(HELLO_WORLD.getBytes());
		byte[] signatureValue = s.sign();

		byte[] convertToXmlDSig = DSSASN1Utils.ensurePlainSignatureValue(EncryptionAlgorithm.ECDSA, signatureValue);
		assertTrue(Utils.isArrayNotEmpty(convertToXmlDSig));

		byte[] asn1xmlsec = SignatureECDSA.convertXMLDSIGtoASN1(convertToXmlDSig);

		Signature s2 = Signature.getInstance("SHA256withECDSA");
		s2.initVerify(pair.getPublic());
		s2.update(HELLO_WORLD.getBytes());
		assertTrue(s2.verify(asn1xmlsec));
	}

	@Test
	public void testECDSA_CVC_ConcatenatedSignature() throws IOException {
		assertCvcSignatureValid("2B9099C9885DDB5BFDA2E9634905B9A63E7E3A6EC87BDC0A89014716B23F00B0AD787FC8D0DCF28F007E7DEC097F30DA892BE2AC61D90997DCDF05740E4D5B0C");
		assertCvcSignatureValid("947b79069e6a1e3316ec15d696649a4b67c6c188df9bc05458f3b0b94907f3fb52522d4cae24a75735969cff556b1476a5ccbe37ca65a928782c14f299f3b2d3");
		assertCvcSignatureValid("28a1583e58e93a661322f776618d83b023bdc52b2e909cf9d53030b9260ed667b588fd39eeee5b1b55523a7e71cb4187d8b1bbf56c1581fc845863157d279cf5");
		assertCvcSignatureValid("dd8fc5414eda2920d347f3d3f9f604fcf09392a8ce3807f6f87d006cf8ed1959075af8abbb030e6990da52fe49c93486a4b98bb2e18e0f84095175eddabfbb96");
		assertCvcSignatureValid("1daf408ead014bba9f243849ece308b31f898e1ce97b54a78b3c15eb103fa8a1c87bdd97fdfc4cb56a7e1e5650dee2ebfff0b56d5a2ca0338e6ed59689e27ae1323f32b0f93b41987a816c93c00462c68c609692084dbced7308a8a66f0365ee5b7b272273e8abd4ddd4a49d2fd67964bc8c757114791446b9716f3b7f551608");
		assertCvcSignatureValid("0d2fc9f18d816e9054af943c392dd46f09da71521de9bd98d765e170f12eb086d3d0f9754105001ed2e703d7290ac967642bc70bdd7a96b5c2b8e3d4b503b80e");
		assertCvcSignatureValid("065a15bd4fec67a2a302d9d3ec679cb8f298f9d6a1d855d3dbf39b3f2fa7ea461e437d9542c4a9527afe5e78c1412937f0dbb05a78380cfb2e1bf6eff944581a");
		assertCvcSignatureValid("f322898717aada9b027855848fa6ec5c4bf84d67a70f0ecbafea9dc90fc1d4f0901325766b199bdcfce1f99a54f0b72e71d740b355fff84a5873fd36c439236e");
		assertCvcSignatureValid("B003267151210F7D8D1A747EEC73A0185CC0E848BF885A9DDE061AB5FB19FB3B6249F8B7B84432738EE80DDAB9654DEA5C4DAB2EC34A5EC8DB17E3DFBF577521");
		assertCvcSignatureValid("C511529B789F64466FE1D524AF9279BEED2F12429798FE0B920F9784A6EBB6400081949A7EE84803E823263CD528F5CE503593F00010191D382B092338AF2E96");
	}

	private void assertCvcSignatureValid(String cvcSignatureInHex) throws IOException {
		byte[] signatureValue = DatatypeConverter.parseHexBinary(cvcSignatureInHex);
		byte[] xmlDSigValue = DSSASN1Utils.ensurePlainSignatureValue(EncryptionAlgorithm.ECDSA, signatureValue);
		assertArrayEquals(signatureValue, xmlDSigValue);

		byte[] asn1Value = SignatureECDSA.convertXMLDSIGtoASN1(signatureValue);
		assertArrayEquals(asn1Value, DSSASN1Utils.toStandardDSASignatureValue(signatureValue));

		byte[] plainSignatureValue = SignatureECDSA.convertASN1toXMLDSIG(asn1Value);
		assertArrayEquals(plainSignatureValue, DSSASN1Utils.toPlainDSASignatureValue(asn1Value));
	}

}
