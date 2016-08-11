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
package eu.europa.esig.dss.tsl;

import java.io.Serializable;
import java.util.Date;

/**
 * Info about a specific trusted list. Immutable.
 * 
 * @author jdvorak
 */
public class TLInfo implements Serializable {

	private static final long serialVersionUID = 1L;

	private final boolean wellSigned;

	private final String territory;

	private final String territoryAsISO3166;

	private final int sequenceNumber;

	private final Date issueDate;

	private final Date nextUpdateDate;

	private final Date loadedDate;

	public TLInfo(boolean wellSigned, String territory, int sequenceNumber, Date issueDate, Date nextUpdateDate,
			Date loadedDate) {
		super();
		this.wellSigned = wellSigned;
		this.territory = territory;
		this.territoryAsISO3166 = ("UK".equals(territory)) ? "GB" : ("EL".equals(territory)) ? "GR" : territory;
		this.sequenceNumber = sequenceNumber;
		this.issueDate = issueDate;
		this.nextUpdateDate = nextUpdateDate;
		this.loadedDate = loadedDate;
	}

	public boolean isWellSigned() {
		return wellSigned;
	}

	public String getTerritory() {
		return territory;
	}

	public String getTerritoryAsISO3166() {
		return territoryAsISO3166;
	}

	public int getSequenceNumber() {
		return sequenceNumber;
	}

	public Date getIssueDate() {
		return issueDate;
	}

	public Date getNextUpdateDate() {
		return nextUpdateDate;
	}

	public Date getLoadedDate() {
		return loadedDate;
	}

	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final TLInfo other = (TLInfo) obj;
		return (wellSigned == other.wellSigned)
				&& ((territory != null) ? territory.equals(other.territory) : other.territory == null)
				&& (sequenceNumber == other.sequenceNumber)
				&& ((issueDate != null) ? issueDate.equals(other.issueDate) : other.issueDate == null);
	}

	public int hashCode() {
		final int prime = 31;
		int result = wellSigned ? 1 : 0;
		result = (prime * result) + ((territory == null) ? 0 : territory.hashCode());
		result = (prime * result) + sequenceNumber;
		result = (prime * result) + ((issueDate == null) ? 0 : issueDate.hashCode());
		return result;
	}

	public String toString() {
		return "TrustList " + territory + "#" + sequenceNumber + "{ Issued " + issueDate + "; Next update "
				+ nextUpdateDate + "; Loaded " + loadedDate + "; " + ((wellSigned) ? "well signed" : "NOT WELL SIGNED")
				+ " }";
	}

}
