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

	/** The protected header schema URI for a JAdES signature */
	private static final String JAdES_PROTECTED_HEADER_SCHEMA_URI = "19182-protected-jsonSchema.json";

	/** The protected header schema for a JAdES signature */
	private static final String JAdES_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/19182-protected-jsonSchema.json";

	/** The unprotected header schema URI for a JAdES signature */
	private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_URI = "19182-unprotected-jsonSchema.json";

	/** The unprotected header schema for a JAdES signature */
	private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/19182-unprotected-jsonSchema.json";

	private static final String RFC_SUBDIRECTORY = "rfcs/";

	/** The RFC 7519 schema of definitions */
	private static final String RFC7519_SCHEMA_LOCATION = "/schema/rfcs/rfc7519.json";

	/** The RFC 7519 schema name URI */
	private static final String RFC7519_SCHEMA_URI = "rfc7519.json";

	/** The RFC 7797 schema of definitions */
	private static final String RFC7797_SCHEMA_LOCATION = "/schema/rfcs/rfc7797.json";

	/** The RFC 7797 schema name URI */
	private static final String RFC7797_SCHEMA_URI = "rfc7797.json";

	/** Map of used definition schemas */
	private Map<URI, String> definitions;

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
	public String getJWSSchemaJSON() {
		return JWSUtils.getInstance().getJWSSchemaJSON();
	}

	@Override
	public Map<URI, String> getJWSSchemaDefinitions() {
		return JWSUtils.getInstance().getJWSSchemaDefinitions();
	}

	@Override
	public String getJWSProtectedHeaderSchemaJSON() {
		return JAdES_PROTECTED_HEADER_SCHEMA_URI;
	}

	@Override
	public Map<URI, String> getJWSProtectedHeaderSchemaDefinitions() {
		return getJAdESDefinitions();
	}

	@Override
	public String getJWSUnprotectedHeaderSchemaJSON() {
		return JAdES_UNPROTECTED_HEADER_SCHEMA_URI;
	}

	@Override
	public Map<URI, String> getJWSUnprotectedHeaderSchemaDefinitions() {
		return getJAdESDefinitions();
	}

	/**
	 * Returns a list of RFC 7515 and RFC 7517 definitions
	 * 
	 * @return a map of definitions
	 */
	public Map<URI, String> getJAdESDefinitions() {
		if (definitions == null) {
			definitions = new HashMap<>();
			definitions.put(URI.create(JAdES_SCHEMA_DEFINITIONS_URI), JAdES_SCHEMA_DEFINITIONS_LOCATION);
			definitions.put(URI.create(JAdES_PROTECTED_HEADER_SCHEMA_URI), JAdES_PROTECTED_HEADER_SCHEMA_LOCATION);
			definitions.put(URI.create(JAdES_UNPROTECTED_HEADER_SCHEMA_URI), JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION);

			Map<URI, String> rfcDefinitions = JWSUtils.getInstance().getRFCDefinitions();
			for (Map.Entry<URI, String> entry : rfcDefinitions.entrySet()) {
				definitions.put(URI.create(RFC_SUBDIRECTORY + entry.getKey().toString()), entry.getValue());
			}
			definitions.put(URI.create(RFC_SUBDIRECTORY + RFC7519_SCHEMA_URI), RFC7519_SCHEMA_LOCATION);
			definitions.put(URI.create(RFC_SUBDIRECTORY + RFC7797_SCHEMA_URI), RFC7797_SCHEMA_LOCATION);

		}
		return definitions;
	}

}
