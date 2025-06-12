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

import eu.europa.esig.json.JSONSchemaAbstractUtils;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Abstract class for JWS signature validation against JSON schemas
 *
 */
public abstract class AbstractJWSUtils extends JSONSchemaAbstractUtils {

	/** The RFC 7515 schema of definitions */
	protected static final String RFC7515_SCHEMA_LOCATION = "/schema/rfc7515.json";

	/** The RFC 7515 schema name URI */
	protected static final String RFC7515_SCHEMA_URI = "rfc7515.json";

	/** The RFC 7517 schema of definitions */
	protected static final String RFC7517_SCHEMA_LOCATION = "/schema/rfc7517.json";

	/** The RFC 7517 schema name URI */
	protected static final String RFC7517_SCHEMA_URI = "rfc7517.json";

	/**
	 * Default constructor
	 */
	protected AbstractJWSUtils() {
		// empty
	}

	/**
	 * Gets a map of RFC definitions
	 *
	 * @return a map between schema URI's and JSON schema file locations
	 */
	public Map<URI, String> getRFCDefinitions() {
		Map<URI, String> definitions = new HashMap<>();
		definitions.put(URI.create(RFC7515_SCHEMA_URI), RFC7515_SCHEMA_LOCATION);
		definitions.put(URI.create(RFC7517_SCHEMA_URI), RFC7517_SCHEMA_LOCATION);
		return definitions;
	}

}
