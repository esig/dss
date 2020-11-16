package eu.europa.esig.jws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Base64;
import java.util.List;

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
		assertEquals(6, errors.size());
		assertErrorFound(errors, "evilPayload");

		String protectedBase64 = jws.getString("protected");
		assertNotNull(protectedBase64);
		
		byte[] decodedProtected = Base64.getDecoder().decode(protectedBase64);
		String protectedString = new String(decodedProtected);
		
		errors = jadesUtils.validateAgainstJWSProtectedHeaderSchema(protectedString);
		assertEquals(1, errors.size());
		assertErrorFound(errors, "x5t");

		JSONObject header = jws.getJSONObject("header");
		assertNotNull(header);
		
		errors = jadesUtils.validateAgainstJWSUnprotectedHeaderSchema(header);
		assertEquals(4, errors.size());
		assertErrorFound(errors, "x509Cert");
		assertErrorFound(errors, "kid");
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
