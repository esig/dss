package eu.europa.esig.jws;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;

public final class JWSUtils extends AbstractJWSUtils {
	
	private static final String JWS_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-protected.json";
	private static final String JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-unprotected.json";

	private static final String RFC7515_SCHEMA_LOCATION = "/schema/rfc7515-definitions.json";
	private static final String RFC7515_SCHEMA_URI = "rfc7515.json";

	private static final String RFC7517_SCHEMA_LOCATION = "/schema/rfc7517-definitions.json";
	private static final String RFC7517_SCHEMA_URI = "rfc7517.json";

	private static final String JWS_SCHEMA_LOCATION = "/schema/rfc7515-jws.json";

	private Map<URI, JSONObject> definitions;

	private static JWSUtils singleton;

	private JWSUtils() {
	}
	
	public static JWSUtils getInstance() {
		if (singleton == null) {
			singleton = new JWSUtils();
		}
		 return singleton;
	}

	@Override
	public JSONObject getJWSSchemaJSON() {
		return parseJson(AbstractJWSUtils.class.getResourceAsStream(JWS_SCHEMA_LOCATION));
	}

	@Override
	public Map<URI, JSONObject> getJWSSchemaDefinitions() {
		return getRFCDefinitions();
	}

	@Override
	public JSONObject getJWSProtectedHeaderSchemaJSON() {
		return parseJson(JWSUtils.class.getResourceAsStream(JWS_PROTECTED_HEADER_SCHEMA_LOCATION));
	}

	@Override
	public Map<URI, JSONObject> getJWSProtectedHeaderSchemaDefinitions() {
		return getRFCDefinitions();
	}

	@Override
	public JSONObject getJWSUnprotectedHeaderSchemaJSON() {
		return parseJson(JWSUtils.class.getResourceAsStream(JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION));
	}

	@Override
	public Map<URI, JSONObject> getJWSUnprotectedHeaderSchemaDefinitions() {
		return getRFCDefinitions();
	}

	/**
	 * Returns a list of RFC 7515 and RFC 7517 definitions
	 * 
	 * @return a map of definitions
	 */
	public Map<URI, JSONObject> getRFCDefinitions() {
		if (definitions == null) {
			definitions = new HashMap<>();
			definitions.put(URI.create(RFC7515_SCHEMA_URI),
					parseJson(JWSUtils.class.getResourceAsStream(RFC7515_SCHEMA_LOCATION)));
			definitions.put(URI.create(RFC7517_SCHEMA_URI),
					parseJson(JWSUtils.class.getResourceAsStream(RFC7517_SCHEMA_LOCATION)));
		}
		return definitions;
	}

}
