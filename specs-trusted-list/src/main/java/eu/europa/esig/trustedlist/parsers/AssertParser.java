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
package eu.europa.esig.trustedlist.parsers;

import eu.europa.esig.trustedlist.enums.Assert;

/**
 * {@code Assert} parser
 */
public final class AssertParser {

	/**
	 * Default constructor
	 */
	private AssertParser() {
		// empty
	}

	/**
	 * Parses the string value and returns {@code Assert}
	 *
	 * @param v {@link String}
	 * @return {@link Assert}, null if not able to parse
	 */
	public static Assert parse(String v) {
		if (v != null) {
			for (Assert a : Assert.values()) {
				if (a.getValue().equals(v)) {
					return a;
				}
			}
		}
		return null;
	}

	/**
	 * Returns value of the {@code Assert}
	 *
	 * @param a {@link Assert}
	 * @return {@link String} value
	 */
	public static String print(Assert a) {
		if (a != null) {
			return a.getValue();
		}
		return null;
	}

}
