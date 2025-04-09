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
import java.util.Map;

/**
 * Contains utils for JWS signature validation against JSON schemas
 *
 */
public final class JWSUtils extends AbstractJWSUtils {

	/** The main JWS signature wrapper schema URI */
	private static final String JWS_SCHEMA_URI = "rfc7515-jws.json";

	/** The main JWS signature wrapper schema */
	private static final String JWS_SCHEMA_LOCATION = "/schema/rfc7515-jws.json";

	/** Singleton instance */
	private static JWSUtils singleton;

	/**
	 * Empty constructor
	 */
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
	public String getSchemaURI() {
		return JWS_SCHEMA_URI;
	}

	@Override
	public Map<URI, String> getSchemaDefinitions() {
		Map<URI, String> definitions = getJSONSchemaDefinitions();
		definitions.putAll(getRFCDefinitions());
		definitions.put(URI.create(JWS_SCHEMA_URI), JWS_SCHEMA_LOCATION);
		return definitions;
	}

}
