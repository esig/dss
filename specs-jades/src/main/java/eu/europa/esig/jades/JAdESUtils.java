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
package eu.europa.esig.jades;

import eu.europa.esig.jws.JWSUtils;

import java.net.URI;
import java.util.Map;

/**
 * Contains utils for JAdES signature validation against JSON schemas
 *
 */
public final class JAdESUtils extends AbstractJAdESUtils {

	/** Singleton instance */
	private static JAdESUtils singleton;

	/**
	 * Empty constructor
	 */
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
	public String getSchemaURI() {
		return JWSUtils.getInstance().getSchemaURI();
	}

	@Override
	public Map<URI, String> getSchemaDefinitions() {
		return JWSUtils.getInstance().getSchemaDefinitions();
	}

}
