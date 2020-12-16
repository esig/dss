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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.jades.validation.JWSSerializationDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class JWSConverterTest {

	@Test
	public void testNotJSONCompact() {
		InMemoryDocument helloDoc = new InMemoryDocument("Hello".getBytes());
		DSSException exception = assertThrows(DSSException.class, () -> JWSConverter.fromJWSCompactToJSONFlattenedSerialization(helloDoc));
		assertEquals("Unable to instantiate a compact JWS", exception.getMessage());
		exception = assertThrows(DSSException.class, () -> JWSConverter.fromJWSCompactToJSONSerialization(helloDoc));
		assertEquals("Unable to instantiate a compact JWS", exception.getMessage());
	}

	@Test
	public void test3Parts() {
		JWSSerializationDocumentValidator validator = new JWSSerializationDocumentValidator();

		DSSDocument jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A".getBytes());
		DSSDocument converted = JWSConverter.fromJWSCompactToJSONFlattenedSerialization(jws);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());
		assertTrue(validator.isSupported(converted));

		converted = JWSConverter.fromJWSCompactToJSONSerialization(jws);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());
		assertTrue(validator.isSupported(converted));
	}

	@Test
	public void test2Parts() {
		JWSSerializationDocumentValidator validator = new JWSSerializationDocumentValidator();

		DSSDocument jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA".getBytes());
		DSSDocument converted = JWSConverter.fromJWSCompactToJSONFlattenedSerialization(jws);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());
		assertTrue(validator.isSupported(converted));

		converted = JWSConverter.fromJWSCompactToJSONSerialization(jws);
		assertNotNull(converted);
		assertNotNull(converted.getMimeType());
		assertNotNull(converted.getName());
		assertTrue(validator.isSupported(converted));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testConvertEtsiUToBase64Url() {
		DSSDocument jwsDocument = new FileDocument("src/test/resources/validation/jades-t-clear-etsiu.json");

		JWSJsonSerializationParser parser = new JWSJsonSerializationParser(jwsDocument);
		JWSJsonSerializationObject jsonSerializationObject = parser.parse();
		List<JWS> signatures = jsonSerializationObject.getSignatures();
		assertEquals(1, signatures.size());

		JWS originalJWS = signatures.get(0);

		Map<String, Object> unprotected = originalJWS.getUnprotected();
		assertEquals(1, unprotected.size());

		List<Object> etsiU = (List<Object>) unprotected.get("etsiU");
		assertEquals(1, etsiU.size());

		Object item = etsiU.get(0);
		assertTrue(item instanceof Map);

		DSSDocument convertedDocument = JWSConverter.fromEtsiUWithClearJsonToBase64UrlIncorporation(jwsDocument);

		parser = new JWSJsonSerializationParser(convertedDocument);
		jsonSerializationObject = parser.parse();

		signatures = jsonSerializationObject.getSignatures();
		assertEquals(1, signatures.size());

		JWS convertedJWS = signatures.get(0);

		assertEquals(originalJWS.getUnverifiedPayload(), convertedJWS.getUnverifiedPayload());
		assertEquals(originalJWS.getEncodedHeader(), convertedJWS.getEncodedHeader());
		assertEquals(originalJWS.getEncodedSignature(), convertedJWS.getEncodedSignature());

		unprotected = convertedJWS.getUnprotected();
		assertEquals(1, unprotected.size());

		etsiU = (List<Object>) unprotected.get("etsiU");
		assertEquals(1, etsiU.size());

		item = etsiU.get(0);
		assertTrue(item instanceof String);
		assertTrue(DSSJsonUtils.isBase64UrlEncoded((String) item));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testConvertEtsiUToClearRepresentation() {
		DSSDocument jwsDocument = new FileDocument("src/test/resources/validation/jades-with-counter-signature.json");

		JWSJsonSerializationParser parser = new JWSJsonSerializationParser(jwsDocument);
		JWSJsonSerializationObject jsonSerializationObject = parser.parse();
		List<JWS> signatures = jsonSerializationObject.getSignatures();
		assertEquals(1, signatures.size());

		JWS originalJWS = signatures.get(0);

		Map<String, Object> unprotected = originalJWS.getUnprotected();
		assertEquals(1, unprotected.size());

		List<Object> etsiU = (List<Object>) unprotected.get("etsiU");
		assertEquals(1, etsiU.size());

		Object item = etsiU.get(0);
		assertTrue(item instanceof String);
		assertTrue(DSSJsonUtils.isBase64UrlEncoded((String) item));

		DSSDocument convertedDocument = JWSConverter.fromEtsiUWithBase64UrlToClearJsonIncorporation(jwsDocument);

		parser = new JWSJsonSerializationParser(convertedDocument);
		jsonSerializationObject = parser.parse();

		signatures = jsonSerializationObject.getSignatures();
		assertEquals(1, signatures.size());

		JWS convertedJWS = signatures.get(0);

		assertEquals(originalJWS.getUnverifiedPayload(), convertedJWS.getUnverifiedPayload());
		assertEquals(originalJWS.getEncodedHeader(), convertedJWS.getEncodedHeader());
		assertEquals(originalJWS.getEncodedSignature(), convertedJWS.getEncodedSignature());

		unprotected = convertedJWS.getUnprotected();
		assertEquals(1, unprotected.size());

		etsiU = (List<Object>) unprotected.get("etsiU");
		assertEquals(1, etsiU.size());

		item = etsiU.get(0);
		assertTrue(item instanceof Map);
	}

	@Test
	public void testConvertWithTimestamp() {
		DSSDocument jwsDocument = new FileDocument("src/test/resources/validation/jades-lta.json");

		Exception exception = assertThrows(DSSException.class,
				() -> JWSConverter.fromEtsiUWithBase64UrlToClearJsonIncorporation(jwsDocument));
		assertEquals("Unable to convert a signature! 'etsiU' contains a component with name "
				+ "'arcTst', which is sensible to a format change.", exception.getMessage());
	}

	@Test
	public void testConvertWithMixedEtsiU() {
		DSSDocument jwsDocument = new FileDocument("src/test/resources/validation/jades-with-mixed-etsiU-type.json");

		Exception exception = assertThrows(DSSException.class,
				() -> JWSConverter.fromEtsiUWithBase64UrlToClearJsonIncorporation(jwsDocument));
		assertEquals("Unable to convert the EtsiU content! All components shall have a common form.",
				exception.getMessage());

		exception = assertThrows(DSSException.class,
				() -> JWSConverter.fromEtsiUWithClearJsonToBase64UrlIncorporation(jwsDocument));
		assertEquals("Unable to convert the EtsiU content! All components shall have a common form.",
				exception.getMessage());
	}

}
