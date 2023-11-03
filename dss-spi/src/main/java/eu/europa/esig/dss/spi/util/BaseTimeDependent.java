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
package eu.europa.esig.dss.spi.util;

import java.util.Date;

/**
 * The default implementation of a time dependent interval
 */
public class BaseTimeDependent implements TimeDependent {

	private static final long serialVersionUID = -6972849560865304279L;

	/** The start of validity date */
	private Date startDate;

	/** The end of validity date */
	private Date endDate;

	/**
	 * Empty constructor
	 */
	public BaseTimeDependent() {
		super();
	}

	/**
	 * Default constructor
	 *
	 * @param startDate {@link Date} start of the validity
	 * @param endDate {@link Date} end of the validity
	 */
	public BaseTimeDependent(final Date startDate, final Date endDate) {
		this.startDate = startDate;
		this.endDate = endDate;
	}
	
	@Override
	public Date getStartDate() {
		return startDate;
	}
	
	@Override
	public Date getEndDate() {
		return endDate;
	}

	@Override
	public String toString() {
		return "[startDate=" + startDate + ", endDate=" + endDate + "]";
	}

}
