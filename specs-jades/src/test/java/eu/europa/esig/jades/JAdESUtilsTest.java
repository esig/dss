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

import com.github.erosb.jsonsKema.JsonArray;
import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonString;
import com.github.erosb.jsonsKema.JsonValue;
import eu.europa.esig.json.JSONParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;

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
		JsonObject jws = new JSONParser().parse(is);
		
		List<String> errors = jadesUtils.validateAgainstSchema(jws);
		assertTrue(errors.isEmpty());

		validateSignature(jws);
	}

	@Test
	void jsonFlattenedInvalidTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-lta-invalid.json");
		JsonObject jws = new JSONParser().parse(is);
		
		List<String> errors = jadesUtils.validateAgainstSchema(jws);
		assertErrorFound(errors, "evilPayload");

		JsonString protectedBase64 = (JsonString) jws.get("protected");
		assertNotNull(protectedBase64);
		assertNotNull(protectedBase64.getValue());

		String protectedBase64String = protectedBase64.getValue();
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64String);
		String protectedString = new String(decodedProtected);
		
		errors = jadesProtectedHeaderUtils.validateAgainstSchema(protectedString);
		assertErrorFound(errors, "x5t");

		JsonObject header = (JsonObject) jws.get("header");
		assertNotNull(header);
		
		errors = jAdESUnprotectedHeaderUtils.validateAgainstSchema(header);
		assertErrorFound(errors, "x509Cert");
	}

	@Test
	void jsonSerializationTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-with-sigPSt.json");
		JsonObject jws = new JSONParser().parse(is);

		List<String> errors = jadesUtils.validateAgainstSchema(jws);
		assertTrue(errors.isEmpty());

		JsonArray jsonArray = (JsonArray) jws.get("signatures");
		assertEquals(1, jsonArray.length());

		JsonObject signature = (JsonObject) jsonArray.get(0);
		validateSignature(signature);
	}

	@Test
	void jsonSerializationInvalidTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-with-sigPSt-invalid.json");
		JsonObject jws = new JSONParser().parse(is);

		List<String> errors = jadesUtils.validateAgainstSchema(jws);
		assertErrorFound(errors, "signature");

		JsonArray jsonArray = (JsonArray) jws.get("signatures");
		assertEquals(1, jsonArray.length());

		JsonObject signature = (JsonObject) jsonArray.get(0);

		JsonString protectedBase64 = (JsonString) signature.get("protected");
		assertNotNull(protectedBase64);
		assertNotNull(protectedBase64.getValue());

		String protectedBase64String = protectedBase64.getValue();

		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64String);
		String protectedString = new String(decodedProtected);

		errors = jadesProtectedHeaderUtils.validateAgainstSchema(protectedString);
		assertErrorFound(errors, "hashAV");

		JsonObject header = (JsonObject) signature.get("header");
		assertNotNull(header);

		errors = jAdESUnprotectedHeaderUtils.validateAgainstSchema(header);
		assertErrorFound(errors, "tstokens");
		assertErrorFound(errors, "sigPSt");
	}

	private void validateSignature(JsonObject signature) {
		JsonString protectedBase64 = (JsonString) signature.get("protected");
		assertNotNull(protectedBase64);
		assertNotNull(protectedBase64.getValue());

		String protectedBase64String = protectedBase64.getValue();

		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64String);
		String protectedString = new String(decodedProtected);

		List<String> errors = jadesProtectedHeaderUtils.validateAgainstSchema(protectedString);
		assertTrue(errors.isEmpty());

		JsonObject header = (JsonObject) signature.get("header");
		assertNotNull(header);

		Map<JsonString, JsonValue> properties = header.getProperties();
		assertNotNull(header.getProperties());
		assertFalse(properties.isEmpty());

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
