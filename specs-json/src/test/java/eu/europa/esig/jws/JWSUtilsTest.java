package eu.europa.esig.jws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Base64;
import java.util.Iterator;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class JWSUtilsTest {
	
	private static JWSUtils jwsUtils;
	
	@BeforeAll
	public static void init() {
		jwsUtils = JWSUtils.getInstance();
	}
	
	@Test
	public void jsonSerializationTest() {
		InputStream is = JWSUtilsTest.class.getResourceAsStream("/jws-serialization.json");
		JSONObject jws = jwsUtils.parseJson(is);
		
		String errors = jwsUtils.validateAgainstJWSSchema(jws);
		assertEquals("", errors);
		
		JSONArray signartures = jws.getJSONArray("signatures");
		assertNotNull(signartures);
		assertTrue(signartures.length() > 0);
		
		Iterator<Object> iterator = signartures.iterator();
		while (iterator.hasNext()) {
			JSONObject signature = (JSONObject) iterator.next();
			validateSignature(signature);
		}
	}
	
	@Test
	public void jsonFlattenedTest() {
		InputStream is = JWSUtilsTest.class.getResourceAsStream("/jws-flattened.json");
		JSONObject jws = jwsUtils.parseJson(is);
		
		String errors = jwsUtils.validateAgainstJWSSchema(jws);
		assertEquals("", errors);
		
		validateSignature(jws);
	}
	
	private void validateSignature(JSONObject signature) {
		String protectedBase64 = signature.getString("protected");
		assertNotNull(protectedBase64);
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);
		
		String errors = jwsUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertEquals("", errors);

		JSONObject header = signature.getJSONObject("header");
		assertNotNull(header);
		
		errors = jwsUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertEquals("", errors);
	}

}
