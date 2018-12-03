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
package eu.europa.esig.dss.util;

import java.util.Date;

public class BaseTimeDependent implements TimeDependent {

	private Date startDate;
	private Date endDate;
	
	public BaseTimeDependent() {
		super();
	}

	public BaseTimeDependent( final Date startDate, final Date endDate ) {
		super();
		this.startDate = startDate;
		this.endDate = endDate;
	}
	
	@Override
	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate( final Date d ) {
		this.startDate = d;
	}
	
	@Override
	public Date getEndDate() {
		return endDate;
	}
	
	public void setEndDate( final Date d ) {
		this.endDate = d;
	}

	@Override
	public String toString() {
		return "[startDate=" + startDate + ", endDate=" + endDate + "]";
	}

}
