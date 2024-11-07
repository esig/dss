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

	/** The main JWS signature wrapper schema URI */
	private static final String JWS_SCHEMA_URI = "rfc7515-jws.json";

	/** The main JWS signature wrapper schema */
	private static final String JWS_SCHEMA_LOCATION = "/schema/rfc7515-jws.json";

	/** The protected header schema URI for a JWS signature */
	private static final String JWS_PROTECTED_HEADER_SCHEMA_URI = "rfc7515-protected.json";

	/** The protected header schema for a JWS signature */
	private static final String JWS_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-protected.json";

	/** The unprotected header schema URI for a JWS signature */
	private static final String JWS_UNPROTECTED_HEADER_SCHEMA_URI = "rfc7515-unprotected.json";

	/** The unprotected header schema for a JWS signature */
	private static final String JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/rfc7515-unprotected.json";

	/** Map of used definition schemas */
	private Map<URI, String> definitions;

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
	public String getJWSSchemaJSON() {
		return JWS_SCHEMA_URI;
	}

	@Override
	public Map<URI, String> getJWSSchemaDefinitions() {
		return getRFCDefinitions();
	}

	@Override
	public String getJWSProtectedHeaderSchemaJSON() {
		return JWS_PROTECTED_HEADER_SCHEMA_URI;
	}

	@Override
	public Map<URI, String> getJWSProtectedHeaderSchemaDefinitions() {
		return getRFCDefinitions();
	}

	@Override
	public String getJWSUnprotectedHeaderSchemaJSON() {
		return JWS_UNPROTECTED_HEADER_SCHEMA_URI;
	}

	@Override
	public Map<URI, String> getJWSUnprotectedHeaderSchemaDefinitions() {
		return getRFCDefinitions();
	}

	/**
	 * Returns a list of RFC 7515 and RFC 7517 definitions
	 * 
	 * @return a map of definitions
	 */
	public Map<URI, String> getRFCDefinitions() {
		if (definitions == null) {
			definitions = new HashMap<>();
			definitions.putAll(getJSONSchemaDefinitions());
			definitions.put(URI.create(RFC7515_SCHEMA_URI), RFC7515_SCHEMA_LOCATION);
			definitions.put(URI.create(RFC7517_SCHEMA_URI), RFC7517_SCHEMA_LOCATION);
			definitions.put(URI.create(JWS_SCHEMA_URI), JWS_SCHEMA_LOCATION);
			definitions.put(URI.create(JWS_PROTECTED_HEADER_SCHEMA_URI), JWS_PROTECTED_HEADER_SCHEMA_LOCATION);
			definitions.put(URI.create(JWS_UNPROTECTED_HEADER_SCHEMA_URI), JWS_UNPROTECTED_HEADER_SCHEMA_LOCATION);
		}
		return definitions;
	}

}
