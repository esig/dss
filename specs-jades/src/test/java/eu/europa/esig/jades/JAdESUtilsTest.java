/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.jades;

import eu.europa.esig.json.JSONParser;
import eu.europa.esig.json.JsonObjectWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESUtilsTest {

	private static JAdESUtils jadesUtils;
	private static JAdESProtectedHeaderUtils jadesProtectedHeaderUtils;
	private static JAdESUnprotectedHeaderUtils jAdESUnprotectedHeaderUtils;
	
	@BeforeAll
	static void init() {
		jadesUtils = JAdESUtils.getInstance();
		jadesProtectedHeaderUtils = JAdESProtectedHeaderUtils.getInstance();
		jAdESUnprotectedHeaderUtils = JAdESUnprotectedHeaderUtils.getInstance();
	}
	
	@Test
	void jsonFlattenedTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-lta.json");
		JsonObjectWrapper jws = new JSONParser().parse(is);
		
		List<String> errors = jadesUtils.validateAgainstSchema(jws);
		assertTrue(errors.isEmpty());

		validateSignature(jws);
	}

	@Test
	void jsonFlattenedInvalidTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-lta-invalid.json");
		JsonObjectWrapper jws = new JSONParser().parse(is);
		
		List<String> errors = jadesUtils.validateAgainstSchema(jws);
		assertErrorFound(errors, "evilPayload");

		String protectedBase64String = jws.getAsString("protected");
		assertNotNull(protectedBase64String);

		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64String);
		String protectedString = new String(decodedProtected);
		
		errors = jadesProtectedHeaderUtils.validateAgainstSchema(protectedString);
		assertErrorFound(errors, "x5t");

		JsonObjectWrapper header = jws.getAsObject("header");
		assertNotNull(header);
		
		errors = jAdESUnprotectedHeaderUtils.validateAgainstSchema(header);
		assertErrorFound(errors, "x509Cert");
	}

	@Test
	void jsonSerializationTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-with-sigPSt.json");
		JsonObjectWrapper jws = new JSONParser().parse(is);

		List<String> errors = jadesUtils.validateAgainstSchema(jws);
		assertTrue(errors.isEmpty());

		List<JsonObjectWrapper> signatures = jws.getAsObjectList("signatures");
		assertEquals(1, signatures.size());

		JsonObjectWrapper signature = signatures.get(0);
		validateSignature(signature);
	}

	@Test
	void jsonSerializationInvalidTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-with-sigPSt-invalid.json");
		JsonObjectWrapper jws = new JSONParser().parse(is);

		List<String> errors = jadesUtils.validateAgainstSchema(jws);
		assertErrorFound(errors, "signature");

		List<JsonObjectWrapper> signatures = jws.getAsObjectList("signatures");
		assertEquals(1, signatures.size());

		JsonObjectWrapper signature = signatures.get(0);

		String protectedBase64String = signature.getAsString("protected");
		assertNotNull(protectedBase64String);

		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64String);
		String protectedString = new String(decodedProtected);

		errors = jadesProtectedHeaderUtils.validateAgainstSchema(protectedString);
		assertErrorFound(errors, "hashAV");

		JsonObjectWrapper header = signature.getAsObject("header");
		assertNotNull(header);

		errors = jAdESUnprotectedHeaderUtils.validateAgainstSchema(header);
		assertErrorFound(errors, "tstokens");
		assertErrorFound(errors, "sigPSt");
	}

	private void validateSignature(JsonObjectWrapper signature) {
		String protectedBase64String = signature.getAsString("protected");
		assertNotNull(protectedBase64String);

		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64String);
		String protectedString = new String(decodedProtected);

		List<String> errors = jadesProtectedHeaderUtils.validateAgainstSchema(protectedString);
		assertTrue(errors.isEmpty());

		JsonObjectWrapper header = signature.getAsObject("header");
		assertNotNull(header);
		assertFalse(header.isEmpty());

		errors = jAdESUnprotectedHeaderUtils.validateAgainstSchema(header);
		assertTrue(errors.isEmpty());
	}

	private void assertErrorFound(List<String> errors, String errorMessage) {
		boolean errorFound = false;
		for (String error : errors) {
			if (error.contains(errorMessage)) {
				errorFound = true;
				break;
			}
		}
		assertTrue(errorFound);
	}

}
