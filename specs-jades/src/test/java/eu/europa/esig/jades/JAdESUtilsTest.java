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
package eu.europa.esig.jades;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Base64;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class JAdESUtilsTest {
	
	private static JAdESUtils jadesUtils;
	
	@BeforeAll
	public static void init() {
		jadesUtils = JAdESUtils.getInstance();
	}
	
	@Test
	public void jsonFlattenedTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-lta.json");
		JSONObject jws = jadesUtils.parseJson(is);
		
		List<String> errors = jadesUtils.validateAgainstJWSSchema(jws);
		assertTrue(errors.isEmpty());

		validateSignature(jws);
	}

	private void validateSignature(JSONObject signature) {
		String protectedBase64 = signature.getString("protected");
		assertNotNull(protectedBase64);
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);
		
		List<String> errors = jadesUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertTrue(errors.isEmpty());

		JSONObject header = signature.getJSONObject("header");
		assertNotNull(header);
		
		errors = jadesUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertTrue(errors.isEmpty());
	}

	@Test
	public void jsonFlattenedInvalidTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-lta-invalid.json");
		JSONObject jws = jadesUtils.parseJson(is);
		
		List<String> errors = jadesUtils.validateAgainstJWSSchema(jws);
		assertErrorFound(errors, "evilPayload");

		String protectedBase64 = jws.getString("protected");
		assertNotNull(protectedBase64);
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);
		
		errors = jadesUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertErrorFound(errors, "x5t");

		JSONObject header = jws.getJSONObject("header");
		assertNotNull(header);
		
		errors = jadesUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertErrorFound(errors, "x509Cert");
	}

	@Test
	public void jsonSerializationTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-with-sigPSt.json");
		JSONObject jws = jadesUtils.parseJson(is);

		List<String> errors = jadesUtils.validateAgainstJWSSchema(jws);
		assertTrue(errors.isEmpty());

		JSONArray jsonArray = jws.getJSONArray("signatures");
		assertEquals(1, jsonArray.length());

		JSONObject signature = (JSONObject) jsonArray.get(0);
		validateSignature(signature);
	}

	@Test
	public void jsonSerializationInvalidTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-with-sigPSt-invalid.json");
		JSONObject jws = jadesUtils.parseJson(is);

		List<String> errors = jadesUtils.validateAgainstJWSSchema(jws);
		assertErrorFound(errors, "[signature] is not permitted");

		JSONArray jsonArray = jws.getJSONArray("signatures");
		assertEquals(1, jsonArray.length());

		JSONObject signature = (JSONObject) jsonArray.get(0);

		String protectedBase64 = signature.getString("protected");
		assertNotNull(protectedBase64);

		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);

		errors = jadesUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertErrorFound(errors, "[hashAV] is not permitted");

		JSONObject header = signature.getJSONObject("header");
		assertNotNull(header);

		errors = jadesUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertErrorFound(errors, "[tstokens] is not permitted");
		assertErrorFound(errors, "sigPSt: #: 2 subschemas matched instead of one");
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
