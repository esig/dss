package eu.europa.esig.jws;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;

public final class JWSUtils extends AbstractJWSUtils {
	
	private static final String JWK_SCHEMA_LOCATION = "/schema/rfc7517.json";
	private static final String JWK_SCHEMA_URI = "rfc7517.json";
	
	private static final String JWS_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-protected.json";
	private static final String JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-unprotected.json";

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
	public JSONObject getJWSProtectedHeaderSchema() {
		return parseJson(JWSUtils.class.getResourceAsStream(JWS_PROTECTED_HEADER_SCHEMA_LOCATION));
	}

	@Override
	public Map<URI, JSONObject> getJWSProtectedHeaderDefinitions() {
		Map<URI, JSONObject> definitions = new HashMap<>();
		definitions.put(URI.create(JWK_SCHEMA_URI), parseJson(JWSUtils.class.getResourceAsStream(JWK_SCHEMA_LOCATION)));
		return definitions;
	}

	@Override
	protected JSONObject getJWSUnprotectedHeaderSchema() {
		return parseJson(JWSUtils.class.getResourceAsStream(JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION));
	}

	@Override
	protected Map<URI, JSONObject> getJWSUnprotectedHeaderDefinitions() {
		return Collections.emptyMap();
	}

}
