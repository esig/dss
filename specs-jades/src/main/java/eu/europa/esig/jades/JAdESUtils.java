package eu.europa.esig.jades;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;

import eu.europa.esig.jws.AbstractJWSUtils;
import eu.europa.esig.jws.JWSUtils;

public final class JAdESUtils extends AbstractJWSUtils {
	
	private static final String JWS_URI = "rfc7515.json";
	private static final String JWS_PROTECTED_HEADER_URI = "rfc7515-protected.json";
	
	private static final String JAdES_COMPONENTS_SCHEMA_LOCATION = "/schema/esi001982-schema-draft07_v004_dss.json";
	private static final String JAdES_COMPONENTS_URI = "esi001982-schema.json";
	
	private static final String JAdES_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/esi001982-protected.json";
	private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/esi001982-unprotected.json";

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
	protected JSONObject getJWSProtectedHeaderSchema() {
		return parseJson(JAdESUtils.class.getResourceAsStream(JAdES_PROTECTED_HEADER_SCHEMA_LOCATION));
	}

	@Override
	protected Map<URI, JSONObject> getJWSProtectedHeaderDefinitions() {
		Map<URI, JSONObject> definitions = JWSUtils.getInstance().getJWSProtectedHeaderDefinitions();
		definitions.put(URI.create(JWS_PROTECTED_HEADER_URI), JWSUtils.getInstance().getJWSProtectedHeaderSchema());
		definitions.put(URI.create(JAdES_COMPONENTS_URI), parseJson(JWSUtils.class.getResourceAsStream(JAdES_COMPONENTS_SCHEMA_LOCATION)));
		return definitions;
	}

	@Override
	protected JSONObject getJWSUnprotectedHeaderSchema() {
		return parseJson(JAdESUtils.class.getResourceAsStream(JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION));
	}

	@Override
	protected Map<URI, JSONObject> getJWSUnprotectedHeaderDefinitions() {
		Map<URI, JSONObject> definitions = new HashMap<>();
		definitions.put(URI.create(JWS_URI), JWSUtils.getInstance().getJWSSchema());
		definitions.put(URI.create(JAdES_COMPONENTS_URI), parseJson(JWSUtils.class.getResourceAsStream(JAdES_COMPONENTS_SCHEMA_LOCATION)));
		return definitions;
	}

}
