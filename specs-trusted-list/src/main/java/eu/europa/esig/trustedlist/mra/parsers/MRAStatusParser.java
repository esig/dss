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
package eu.europa.esig.trustedlist.mra.parsers;

import eu.europa.esig.dss.enumerations.MRAStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses a {@code MRAStatus} object.
 *
 */
public final class MRAStatusParser {

	private static final Logger LOG = LoggerFactory.getLogger(MRAStatusParser.class);

	/**
	 * Default constructor
	 */
	private MRAStatusParser() {
		// empty
	}

	/**
	 * Parses the {@code String} and returns a {@code MRAStatus}
	 *
	 * @param v {@link String}
	 * @return {@link MRAStatus}
	 */
	public static MRAStatus parse(String v) {
		if (v != null) {
			for (MRAStatus m : MRAStatus.values()) {
				if (m.getUri().equals(v)) {
					return m;
				}
			}
		}
		LOG.warn("Unknown MRAStatus URI : {}", v);
		return null;
	}

	/**
	 * Returns a string representation of {@code String}
	 *
	 * @param m {@link MRAStatus}
	 * @return {@link String}
	 */
	public static String print(MRAStatus m) {
		if (m != null) {
			return m.getUri();
		}
		return null;
	}

}
