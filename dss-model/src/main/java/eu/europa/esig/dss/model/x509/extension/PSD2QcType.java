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
package eu.europa.esig.dss.model.x509.extension;

import java.io.Serializable;
import java.util.List;

/**
 * Represents a PSD-2-QC type
 *
 */
public class PSD2QcType implements Serializable {

	private static final long serialVersionUID = 3691830305051608960L;

	/** A list of {@code RoleOfPSP}s */
	private List<RoleOfPSP> rolesOfPSP;

	/** NCA name */
	private String ncaName;

	/** NCA Id */
	private String ncaId;

	/**
	 * Default constructor instantiating object with null values
	 */
	public PSD2QcType() {
		// empty
	}

	/**
	 * Gets a list of {@code RoleOfPSP}s
	 *
	 * @return a list of {@link RoleOfPSP}s
	 */
	public List<RoleOfPSP> getRolesOfPSP() {
		return rolesOfPSP;
	}

	/**
	 * Sets a list of {@code RoleOfPSP}s
	 *
	 * @param rolesOfPSP a list of {@link RoleOfPSP}s
	 */
	public void setRolesOfPSP(List<RoleOfPSP> rolesOfPSP) {
		this.rolesOfPSP = rolesOfPSP;
	}

	/**
	 * Gets an NCA name
	 *
	 * @return {@link String}
	 */
	public String getNcaName() {
		return ncaName;
	}

	/**
	 * Sets an NCA name
	 *
	 * @param ncaName {@link String}
	 */
	public void setNcaName(String ncaName) {
		this.ncaName = ncaName;
	}

	/**
	 * Gets an NCA Id
	 *
	 * @return {@link String}
	 */
	public String getNcaId() {
		return ncaId;
	}

	/**
	 * Sets an NCA Id
	 *
	 * @param ncaId {@link String}
	 */
	public void setNcaId(String ncaId) {
		this.ncaId = ncaId;
	}

}
