/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.jws;

import org.json.JSONObject;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains utils for JWS signature validation against JSON schemas
 */
public final class JWSUtils extends AbstractJWSUtils {

	/** The RFC 7515 schema of definitions */
	private static final String RFC7515_SCHEMA_LOCATION = "/schema/rfc7515.json";

	/** The RFC 7515 schema name URI */
	private static final String RFC7515_SCHEMA_URI = "rfc7515.json";

	/** The RFC 7517 schema of definitions */
	private static final String RFC7517_SCHEMA_LOCATION = "/schema/rfc7517.json";

	/** The RFC 7517 schema name URI */
	private static final String RFC7517_SCHEMA_URI = "rfc7517.json";

	/** The main JWS signature wrapper schema */
	private static final String JWS_SCHEMA_LOCATION = "/schema/rfc7515-jws.json";

	/** The protected header schema for a JWS signature */
	private static final String JWS_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-protected.json";

	/** The unprotected header schema for a JWS signature */
	private static final String JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-unprotected.json";

	/** Map of used definition schemas */
	private Map<URI, JSONObject> definitions;

	private static JWSUtils singleton;

	private JWSUtils() {
		// empty
	}

	/**
	 * Returns instance of {@code JWSUtils}
	 *
	 * @return {@link JWSUtils}
	 */
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
