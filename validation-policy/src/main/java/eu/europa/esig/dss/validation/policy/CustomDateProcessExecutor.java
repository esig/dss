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
package eu.europa.esig.dss.validation.policy;

import java.util.Date;

import eu.europa.esig.dss.DSSUtils;

/**
 * This class allows to associate a specific date to the validation process.
 */
public class CustomDateProcessExecutor extends CustomProcessExecutor {

	/**
	 * This constructor allows to instantiate the validation context with the given date.
	 *
	 * @param validationDate specific validation date
	 */
	public CustomDateProcessExecutor(final Date validationDate) {

		currentTime = validationDate;
	}

	/**
	 * This constructor allows to instantiate the validation context with the given date expressed as year, month and day.
	 *
	 * @param year  the value used to set the YEAR calendar field.
	 * @param month the month. Month value is 1-based. e.g., 1 for January.
	 * @param day   the value used to set the DAY_OF_MONTH calendar field.
	 */
	public CustomDateProcessExecutor(int year, int month, int day) {

		currentTime = DSSUtils.getUtcDate(year, month - 1, day);
	}
}
