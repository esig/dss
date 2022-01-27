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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;

import java.util.Date;

/**
 * This filter is used to filter TrustedServices that have been valid at the given time
 *
 */
public class ServiceByDateFilter extends AbstractTrustedServiceFilter {

	/** Time to filter by */
	private final Date date;

	/**
	 * Default constructor
	 *
	 * @param date {@link Date} to filter TrustedServices valid at the time
	 */
	public ServiceByDateFilter(Date date) {
		this.date = date;
	}

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		Date startDate = service.getStartDate();
		Date endDate = service.getEndDate();

		if (date == null) { // possible in case of null signing time
			return false;
		}

		boolean afterStartRange = (startDate != null && (date.compareTo(startDate) >= 0));
		boolean beforeEndRange = (endDate == null || (date.compareTo(endDate) <= 0)); // end date can be null (in case
																						// of current status)

		return afterStartRange && beforeEndRange;
	}

}
