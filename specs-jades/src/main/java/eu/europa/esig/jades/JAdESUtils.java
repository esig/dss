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
package eu.europa.esig.jades;

import eu.europa.esig.jws.AbstractJWSUtils;
import eu.europa.esig.jws.JWSUtils;
import org.json.JSONObject;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains utils for JAdES signature validation against JSON schemas
 */
public final class JAdESUtils extends AbstractJWSUtils {

	/** The JAdES schema of definitions */
	private static final String JAdES_SCHEMA_DEFINITIONS_LOCATION = "/schema/19182-jsonSchema.json";

	/** The JAdES schema name URI */
	private static final String JAdES_SCHEMA_DEFINITIONS_URI = "19182-jsonSchema.json";

	/** The protected header schema for a JAdES signature */
	private static final String JAdES_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/19182-protected-jsonSchema.json";

	/** The unprotected header schema for a JAdES signature */
	private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/19182-unprotected-jsonSchema.json";

	private static final String RFC_SUBDIRECTORY = "rfcs/";

	/** The RFC 7797 schema of definitions */
	private static final String RFC7797_SCHEMA_LOCATION = "/schema/rfcs/rfc7797.json";

	/** The RFC 7797 schema name URI */
	private static final String RFC7797_SCHEMA_URI = "rfc7797.json";

	/** Map of used definition schemas */
	private Map<URI, JSONObject> definitions;

	private static JAdESUtils singleton;

	private JAdESUtils() {
		// empty
	}

	/**
	 * Returns instance of {@code JAdESUtils}
	 *
	 * @return {@link JAdESUtils}
	 */
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
			definitions = new HashMap<>();
			definitions.put(URI.create(JAdES_SCHEMA_DEFINITIONS_URI),
					parseJson(JAdESUtils.class.getResourceAsStream(JAdES_SCHEMA_DEFINITIONS_LOCATION)));

			Map<URI, JSONObject> rfcDefinitions = JWSUtils.getInstance().getRFCDefinitions();
			for (Map.Entry<URI, JSONObject> entry : rfcDefinitions.entrySet()) {
				definitions.put(URI.create(RFC_SUBDIRECTORY + entry.getKey().toString()), entry.getValue());
			}
			definitions.put(URI.create(RFC_SUBDIRECTORY + RFC7797_SCHEMA_URI),
					parseJson(JAdESUtils.class.getResourceAsStream(RFC7797_SCHEMA_LOCATION)));

		}
		return definitions;
	}

}
