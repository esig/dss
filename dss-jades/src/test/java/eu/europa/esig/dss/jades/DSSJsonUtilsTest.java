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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSSJsonUtilsTest {
	
	@Test
	public void isBase64UrlEncodedTest() {
		assertTrue(DSSJsonUtils.isBase64UrlEncoded(""));
		assertTrue(DSSJsonUtils.isBase64UrlEncoded("ew0KICAgICJ0aXRsZSI6ICJIZWxsbyBXb3JsZCEiDQp9"));
		assertTrue(DSSJsonUtils.isBase64UrlEncoded(
				"RFssS82MNnGv7ysjlLP11E8D1KpaegAimzl6CtwHATXVnHsDEg6nrLgzEjDWm0bfWHidPAB6J17kGtC1yky8ZA"));
		assertFalse(DSSJsonUtils.isBase64UrlEncoded(null));
		assertFalse(DSSJsonUtils.isBase64UrlEncoded(" "));
		assertFalse(DSSJsonUtils.isBase64UrlEncoded(
				"RFssS82MNnGv7ysjlLP11E8D1KpaegAimzl6CtwHATXVnHsDEg6nrLgzEjDWm0bfWHidPAB6J17kGtC1yky8ZA=="));
	}

	@Test
	public void isUrlSafePayloadTest() {
		assertTrue(DSSJsonUtils.isUrlSafePayload(""));
		assertTrue(DSSJsonUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsbyBXb3JsZCEiDQp9"));
		assertTrue(DSSJsonUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsbyBXb3JsZCEiDQp9???!!!"));
		assertTrue(DSSJsonUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsb yBXb3JsZCEiDQp9"));
		assertFalse(DSSJsonUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsb.yBXb3JsZCEiDQp9"));
		assertFalse(DSSJsonUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsb\nyBXb3JsZCEiDQp9"));
		assertFalse(DSSJsonUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsb\ryBXb3JsZCEiDQp9"));
		assertFalse(DSSJsonUtils.isUrlSafePayload("."));
		assertFalse(DSSJsonUtils.isUrlSafePayload("..."));
	}

	@Test
	public void isUtf8Test() {
		assertTrue(DSSJsonUtils.isUtf8("Some string".getBytes()));
		assertTrue(DSSJsonUtils.isUtf8(new byte[]{ (byte) 0b11001111, (byte) 0b10111111 }));
		assertTrue(DSSJsonUtils.isUtf8(new byte[]{ (byte) 0b11101111, (byte) 0b10101010, (byte) 0b10111111 }));
		assertTrue(DSSJsonUtils.isUtf8("\u24b6".getBytes(StandardCharsets.UTF_8)));
		assertFalse(DSSJsonUtils.isUtf8(new byte[]{ (byte) 0b10001111, (byte) 0b10111111} ));
		assertFalse(DSSJsonUtils.isUtf8(new byte[]{ (byte) 0b10101010, (byte) 0b00111111} ));
	}
	
	@Test
	public void fromAsn1ToRSTest() throws Exception {
		assertSignatureValid("2B9099C9885DDB5BFDA2E9634905B9A63E7E3A6EC87BDC0A89014716B23F00B0AD787FC8D0DCF28F007E7DEC097F30DA892BE2AC61D90997DCDF05740E4D5B0C");
		assertSignatureValid("947b79069e6a1e3316ec15d696649a4b67c6c188df9bc05458f3b0b94907f3fb52522d4cae24a75735969cff556b1476a5ccbe37ca65a928782c14f299f3b2d3");
		assertSignatureValid("28a1583e58e93a661322f776618d83b023bdc52b2e909cf9d53030b9260ed667b588fd39eeee5b1b55523a7e71cb4187d8b1bbf56c1581fc845863157d279cf5");
		assertSignatureValid("dd8fc5414eda2920d347f3d3f9f604fcf09392a8ce3807f6f87d006cf8ed1959075af8abbb030e6990da52fe49c93486a4b98bb2e18e0f84095175eddabfbb96");
		assertSignatureValid("1daf408ead014bba9f243849ece308b31f898e1ce97b54a78b3c15eb103fa8a1c87bdd97fdfc4cb56a7e1e5650dee2ebfff0b56d5a2ca0338e6ed59689e27ae1323f32b0f93b41987a816c93c00462c68c609692084dbced7308a8a66f0365ee5b7b272273e8abd4ddd4a49d2fd67964bc8c757114791446b9716f3b7f551608");
		assertSignatureValid("0d2fc9f18d816e9054af943c392dd46f09da71521de9bd98d765e170f12eb086d3d0f9754105001ed2e703d7290ac967642bc70bdd7a96b5c2b8e3d4b503b80e");
		assertSignatureValid("065a15bd4fec67a2a302d9d3ec679cb8f298f9d6a1d855d3dbf39b3f2fa7ea461e437d9542c4a9527afe5e78c1412937f0dbb05a78380cfb2e1bf6eff944581a");
		assertSignatureValid("f322898717aada9b027855848fa6ec5c4bf84d67a70f0ecbafea9dc90fc1d4f0901325766b199bdcfce1f99a54f0b72e71d740b355fff84a5873fd36c439236e");
		assertSignatureValid("B003267151210F7D8D1A747EEC73A0185CC0E848BF885A9DDE061AB5FB19FB3B6249F8B7B84432738EE80DDAB9654DEA5C4DAB2EC34A5EC8DB17E3DFBF577521");
		assertSignatureValid("C511529B789F64466FE1D524AF9279BEED2F12429798FE0B920F9784A6EBB6400081949A7EE84803E823263CD528F5CE503593F00010191D382B092338AF2E96");
	}

	private void assertSignatureValid(String string) throws Exception {
		byte[] signatureValueConcatenated = Utils.fromHex(string);
		byte[] derEncoded = EcdsaUsingShaAlgorithm.convertConcatenatedToDer(signatureValueConcatenated);
		assertArrayEquals(derEncoded, DSSASN1Utils.toStandardDSASignatureValue(signatureValueConcatenated));
		
		byte[] joseConverted = EcdsaUsingShaAlgorithm.convertDerToConcatenated(derEncoded, 0);
		assertArrayEquals(joseConverted, DSSASN1Utils.toPlainDSASignatureValue(derEncoded));

		byte[] signatureValue = DSSASN1Utils.ensurePlainSignatureValue(EncryptionAlgorithm.ECDSA, derEncoded);
		assertArrayEquals(joseConverted, signatureValue);
	}
	
	@Test
	public void isJSONDocumentTest() {
		FileDocument jsonDoc = new FileDocument("src/test/resources/sample.json");
		assertTrue(DSSJsonUtils.isJsonDocument(jsonDoc));
		assertTrue(DSSJsonUtils.isJsonDocument(new FileDocument("src/test/resources/validation/jades-lta.json")));
		assertFalse(DSSJsonUtils.isJsonDocument(new FileDocument("src/test/resources/validation/simple-detached.json"))); // compact serialization JAdES
		assertFalse(DSSJsonUtils.isJsonDocument(new FileDocument("src/test/resources/sample.png")));
		assertFalse(DSSJsonUtils.isJsonDocument(new InMemoryDocument("Hello World!".getBytes())));
		assertFalse(DSSJsonUtils.isJsonDocument(new HTTPHeader("header", "ByeWorld!")));
		assertFalse(DSSJsonUtils.isJsonDocument(new DigestDocument(DigestAlgorithm.SHA1, Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA1, jsonDoc)))));
	}

}
