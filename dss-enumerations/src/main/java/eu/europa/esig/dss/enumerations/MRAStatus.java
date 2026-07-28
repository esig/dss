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
package eu.europa.esig.dss.enumerations;

/**
 * It specifies the current status of the MRA for the corresponding
 * trust service type identified in the TrustServiceLegalIdentifier field.
 *
 */
public enum MRAStatus implements UriBasedEnum {

	/** Used to denote a valid status */
	ENACTED("http://ec.europa.eu/tools/lotl/mra/enacted"),

	/** Used to denote an invalid status */
	REPEALED("http://ec.europa.eu/tools/lotl/mra/repealed");

	/** Identifies URI of the MRA status */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 */
	MRAStatus(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return this.uri;
	}

	/**
	 * Returns whether the MRA Status corresponds to the enacted Trust Service equivalence schema
	 *
	 * @return TRUE if the Trust Service equivalence schema is enacted, FALSE otherwise
	 */
	public boolean isEnacted() {
		return ENACTED == this;
	}

}
