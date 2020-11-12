package eu.europa.esig.jws;

import java.net.URI;
import java.util.Map;

import org.json.JSONObject;

public final class JAdESUtils extends AbstractJWSUtils {

	private static final String JAdES_SCHEMA_DEFINITIONS_LOCATION = "/schema/esi001982-schema-draft07_v005b_dss.json";
	private static final String JAdES_SCHEMA_DEFINITIONS_URI = "esi001982-schema.json";

	private static final String RFC7797_SCHEMA_LOCATION = "/schema/rfc7797.json";
	private static final String RFC7797_SCHEMA_URI = "rfc7797.json";
	
	private static final String JAdES_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/esi001982-protected.json";
	private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/esi001982-unprotected.json";

	private Map<URI, JSONObject> definitions;

	private static JAdESUtils singleton;

	private JAdESUtils() {
	}
	
	public static JAdESUtils getInstance() {
		if (singleton == null) {
			singleton = new JAdESUtils();
		}
		 return singleton;
	}

	@Override
	public JSONObject getJWSSchemaJSON() {
		return JWSUtils.getInstance().getJWSSchemaJSON();
	}

	@Override
	public Map<URI, JSONObject> getJWSSchemaDefinitions() {
		return JWSUtils.getInstance().getJWSSchemaDefinitions();
	}

	@Override
	public JSONObject getJWSProtectedHeaderSchemaJSON() {
		return parseJson(JAdESUtils.class.getResourceAsStream(JAdES_PROTECTED_HEADER_SCHEMA_LOCATION));
	}

	@Override
	public Map<URI, JSONObject> getJWSProtectedHeaderSchemaDefinitions() {
		return getJAdESDefinitions();
	}

	@Override
	public JSONObject getJWSUnprotectedHeaderSchemaJSON() {
		return parseJson(JAdESUtils.class.getResourceAsStream(JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION));
	}

	@Override
	public Map<URI, JSONObject> getJWSUnprotectedHeaderSchemaDefinitions() {
		return getJAdESDefinitions();
	}

	/**
	 * Returns a list of RFC 7515 and RFC 7517 definitions
	 * 
	 * @return a map of definitions
	 */
	public Map<URI, JSONObject> getJAdESDefinitions() {
		if (definitions == null) {
			definitions = JWSUtils.getInstance().getRFCDefinitions();
			definitions.put(URI.create(JAdES_SCHEMA_DEFINITIONS_URI),
					parseJson(JAdESUtils.class.getResourceAsStream(JAdES_SCHEMA_DEFINITIONS_LOCATION)));
			definitions.put(URI.create(RFC7797_SCHEMA_URI),
					parseJson(JAdESUtils.class.getResourceAsStream(RFC7797_SCHEMA_LOCATION)));
		}
		return definitions;
	}

}
