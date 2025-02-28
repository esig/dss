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
package eu.europa.esig.trustedlist.mra.parsers;

import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses a {@code MRAEquivalenceContext} object.
 *
 */
public final class MRAEquivalenceContextParser {

	private static final Logger LOG = LoggerFactory.getLogger(MRAEquivalenceContextParser.class);

	/**
	 * Default constructor
	 */
	private MRAEquivalenceContextParser() {
		// empty
	}

	/**
	 * Parses the {@code String} and returns a {@code MRAEquivalenceContext}
	 *
	 * @param v {@link String}
	 * @return {@link MRAEquivalenceContext}
	 */
	public static MRAEquivalenceContext parse(String v) {
		if (v != null) {
			for (MRAEquivalenceContext m : MRAEquivalenceContext.values()) {
				if (m.getUri().equals(v)) {
					return m;
				}
			}
		}
		LOG.warn("Unknown MRAEquivalenceContext URI : {}", v);
		return null;
	}

	/**
	 * Returns a string representation of {@code String}
	 *
	 * @param m {@link MRAEquivalenceContext}
	 * @return {@link String}
	 */
	public static String print(MRAEquivalenceContext m) {
		if (m != null) {
			return m.getUri();
		}
		return null;
	}

}
