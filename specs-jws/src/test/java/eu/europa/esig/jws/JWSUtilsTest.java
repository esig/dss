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

import eu.europa.esig.json.JSONParser;
import eu.europa.esig.json.JsonObjectWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWSUtilsTest {

	private static JWSUtils jwsUtils;
	private static JWSProtectedHeaderUtils jwsProtectedHeaderUtils;
	private static JWSUnprotectedHeaderUtils jwsUnprotectedHeaderUtils;
	
	@BeforeAll
	static void init() {
		jwsUtils = JWSUtils.getInstance();
		jwsProtectedHeaderUtils = JWSProtectedHeaderUtils.getInstance();
		jwsUnprotectedHeaderUtils = JWSUnprotectedHeaderUtils.getInstance();
	}
	
	@Test
	void jsonSerializationTest() {
		InputStream is = JWSUtilsTest.class.getResourceAsStream("/jws-serialization.json");
		JsonObjectWrapper jws = new JSONParser().parse(is);
		
		List<String> errors = jwsUtils.validateAgainstSchema(jws);
		assertTrue(errors.isEmpty(), errors.toString());

		List<JsonObjectWrapper> signatures = jws.getAsObjectList("signatures");
		assertNotNull(signatures);
		assertTrue(signatures.size() > 0);

		for (JsonObjectWrapper signature : signatures) {
			validateSignature(signature);
		}
	}
	
	@Test
	void jsonFlattenedTest() {
		InputStream is = JWSUtilsTest.class.getResourceAsStream("/jws-flattened.json");
		JsonObjectWrapper jws = new JSONParser().parse(is);
		
		List<String> errors = jwsUtils.validateAgainstSchema(jws);
		assertTrue(errors.isEmpty());
		
		validateSignature(jws);
	}
	
	private void validateSignature(JsonObjectWrapper signature) {
		String protectedBase64String = signature.getAsString("protected");
		assertNotNull(protectedBase64String);

		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64String);
		String protectedString = new String(decodedProtected);
		
		List<String> errors = jwsProtectedHeaderUtils.validateAgainstSchema(protectedString);
		assertTrue(errors.isEmpty());

		JsonObjectWrapper header = signature.getAsObject("header");
		assertNotNull(header);
		assertFalse(header.isEmpty());
		
		errors = jwsUnprotectedHeaderUtils.validateAgainstSchema(header);
		assertTrue(errors.isEmpty());
	}

}
