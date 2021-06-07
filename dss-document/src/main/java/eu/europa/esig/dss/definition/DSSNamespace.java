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
package eu.europa.esig.dss.definition;

/**
 * Defines the namespaces
 */
public class DSSNamespace {

	/** The namespace URI */
	private final String uri;

	/** The namespace prefix */
	private final String prefix;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 * @param prefix {@link String}
	 */
	public DSSNamespace(String uri, String prefix) {
		this.uri = uri;
		this.prefix = prefix;
	}

	/**
	 * Gets the namespace URI
	 *
	 * @return {@link String}
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Gets the namespace prefix
	 *
	 * @return {@link String}
	 */
	public String getPrefix() {
		return prefix;
	}

	/**
	 * Checks if the given URI is the same as for the current DSSNamespace object
	 *
	 * @param paramUri {@link String}
	 * @return TRUE if the namespace URI matches, FALSE otherwise
	 */
	public boolean isSameUri(String paramUri) {
		return this.uri.equals(paramUri);
	}

	@Override
	public String toString() {
		return "DSSNamespace [uri='" + uri + ", prefix='" + prefix + ']';
	}

}
