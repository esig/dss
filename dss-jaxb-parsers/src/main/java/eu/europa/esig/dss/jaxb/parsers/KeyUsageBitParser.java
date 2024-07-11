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
package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.KeyUsageBit;

/**
 * Parses the {@code KeyUsageBit}
 */
public final class KeyUsageBitParser {

	/**
	 * Default constructor
	 */
	private KeyUsageBitParser() {
		// empty
	}

	/**
	 * Parses the value and returns {@code KeyUsageBit}
	 *
	 * @param v {@link String} to parse
	 * @return {@link KeyUsageBit}
	 */
	public static KeyUsageBit parse(String v) {
		if (v != null) {
			for (KeyUsageBit kub : KeyUsageBit.values()) {
				if (kub.getValue().equals(v)) {
					return kub;
				}
			}
		}
		return null;
	}

	/**
	 * Gets a text name of the value
	 *
	 * @param v {@link KeyUsageBit}
	 * @return {@link String}
	 */
	public static String print(KeyUsageBit v) {
		if (v != null) {
			return v.getValue();
		}
		return null;
	}

}
