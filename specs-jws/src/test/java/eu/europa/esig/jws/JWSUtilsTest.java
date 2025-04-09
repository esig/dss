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
package eu.europa.esig.jws;

import com.github.erosb.jsonsKema.JsonArray;
import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonString;
import com.github.erosb.jsonsKema.JsonValue;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWSUtilsTest {
	
	private static JSONUtils jsonUtils;
	private static JWSUtils jwsUtils;
	
	@BeforeAll
	static void init() {
		jsonUtils = JSONUtils.getInstance();
		jwsUtils = JWSUtils.getInstance();
	}
	
	@Test
	void jsonSerializationTest() {
		InputStream is = JWSUtilsTest.class.getResourceAsStream("/jws-serialization.json");
		JsonObject jws = jsonUtils.parseJson(is);
		
		List<String> errors = jwsUtils.validateAgainstJWSSchema(jws);
		assertTrue(errors.isEmpty(), errors.toString());

		JsonArray signatures = (JsonArray) jws.get("signatures");
		assertNotNull(signatures);
		assertTrue(signatures.length() > 0);

		for (JsonValue signature : signatures.getElements()) {
			JsonObject jsonSignature = (JsonObject) signature;
			validateSignature(jsonSignature);
		}
	}
	
	@Test
	void jsonFlattenedTest() {
		InputStream is = JWSUtilsTest.class.getResourceAsStream("/jws-flattened.json");
		JsonObject jws = jsonUtils.parseJson(is);
		
		List<String> errors = jwsUtils.validateAgainstJWSSchema(jws);
		assertTrue(errors.isEmpty());
		
		validateSignature(jws);
	}
	
	private void validateSignature(JsonObject signature) {
		JsonString protectedBase64 = (JsonString) signature.get("protected");
		assertNotNull(protectedBase64);
		assertNotNull(protectedBase64.getValue());

		String protectedBase64String = protectedBase64.getValue();
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64String);
		String protectedString = new String(decodedProtected);
		
		List<String> errors = jwsUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertTrue(errors.isEmpty());

		JsonObject header = (JsonObject) signature.get("header");
		assertNotNull(header);

		Map<JsonString, JsonValue> properties = header.getProperties();
		assertNotNull(header.getProperties());
		assertFalse(properties.isEmpty());
		
		errors = jwsUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertTrue(errors.isEmpty());
	}

}
