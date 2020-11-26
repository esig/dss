package eu.europa.esig.jws;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

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
		
		List<String> errors = jwsUtils.validateAgainstJWSSchema(jws);
		assertTrue(errors.isEmpty(), errors.toString());
		
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
		
		List<String> errors = jwsUtils.validateAgainstJWSSchema(jws);
		assertTrue(errors.isEmpty());
		
		validateSignature(jws);
	}
	
	private void validateSignature(JSONObject signature) {
		String protectedBase64 = signature.getString("protected");
		assertNotNull(protectedBase64);
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);
		
		List<String> errors = jwsUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertTrue(errors.isEmpty());

		JSONObject header = signature.getJSONObject("header");
		assertNotNull(header);
		
		errors = jwsUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertTrue(errors.isEmpty());
	}

}
