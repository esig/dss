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
package eu.europa.esig.dss.xml.common.definition;

import java.io.Serializable;

/**
 * The XML element
 */
public interface DSSElement extends Serializable {

	/**
	 * Returns element tag name
	 *
	 * @return {@link String} element tag name
	 */
	String getTagName();

	/**
	 * Returns the namespace
	 *
	 * @return {@link DSSNamespace}
	 */
	DSSNamespace getNamespace();

	/**
	 * Returns namespace URI
	 *
	 * @return {@link String} uri
	 */
	String getURI();

	/**
	 * Checks if the tag name matches to the current element
	 *
	 * @param value {@link String} element name to compare
	 * @return TRUE if the value matches, FALSE otherwise
	 */
	boolean isSameTagName(String value);

}
