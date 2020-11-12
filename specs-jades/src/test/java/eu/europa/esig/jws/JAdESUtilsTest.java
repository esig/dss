package eu.europa.esig.jws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Base64;

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
		
		String errors = jadesUtils.validateAgainstJWSSchema(jws);
		assertEquals("", errors);

		validateSignature(jws);
	}

	private void validateSignature(JSONObject signature) {
		String protectedBase64 = signature.getString("protected");
		assertNotNull(protectedBase64);
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);
		
		String errors = jadesUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertEquals("", errors);

		JSONObject header = signature.getJSONObject("header");
		assertNotNull(header);
		
		errors = jadesUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertEquals("", errors);
	}

	@Test
	public void jsonFlattenedInvalidTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-lta-invalid.json");
		JSONObject jws = jadesUtils.parseJson(is);
		
		String errors = jadesUtils.validateAgainstJWSSchema(jws);
		assertTrue(errors.contains("evilPayload"));

		String protectedBase64 = jws.getString("protected");
		assertNotNull(protectedBase64);
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);
		
		errors = jadesUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertTrue(errors.contains("x5t"));

		JSONObject header = jws.getJSONObject("header");
		assertNotNull(header);
		
		errors = jadesUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertTrue(errors.contains("x509Cert"));
	}

	@Test
	public void jsonSerializationTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-with-sigPSt.json");
		JSONObject jws = jadesUtils.parseJson(is);

		String errors = jadesUtils.validateAgainstJWSSchema(jws);
		assertEquals("", errors);

		JSONArray jsonArray = jws.getJSONArray("signatures");
		assertEquals(1, jsonArray.length());

		JSONObject signature = (JSONObject) jsonArray.get(0);
		validateSignature(signature);
	}

	@Test
	public void jsonSerializationInvalidTest() {
		InputStream is = JAdESUtilsTest.class.getResourceAsStream("/jades-with-sigPSt-invalid.json");
		JSONObject jws = jadesUtils.parseJson(is);

		String errors = jadesUtils.validateAgainstJWSSchema(jws);
		assertTrue(errors.contains("[signature] is not permitted"));

		JSONArray jsonArray = jws.getJSONArray("signatures");
		assertEquals(1, jsonArray.length());

		JSONObject signature = (JSONObject) jsonArray.get(0);

		String protectedBase64 = signature.getString("protected");
		assertNotNull(protectedBase64);

		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);

		errors = jadesUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertTrue(errors.contains("[hashAV] is not permitted"));

		JSONObject header = signature.getJSONObject("header");
		assertNotNull(header);

		errors = jadesUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertTrue(errors.contains("[tstokens] is not permitted"));
		assertTrue(errors.contains("sigPSt: #: 2 subschemas matched instead of one"));
	}

}
