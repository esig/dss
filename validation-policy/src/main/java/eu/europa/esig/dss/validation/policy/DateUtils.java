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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import eu.europa.esig.dss.DSSException;

public final class DateUtils {

	public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

	private DateUtils() {
	}

	/**
	 * Converts the given string representation of the date using the format pattern.
	 *
	 * @param format
	 *            the format to use
	 * @param dateString
	 *            the date string representation
	 * @return the {@code Date}
	 * @throws DSSException
	 *             if the conversion is not possible the {@code DSSException} is thrown.
	 */
	public static Date parseDate(final String format, final String dateString) {
		try {
			final SimpleDateFormat sdf = new SimpleDateFormat(format);
			sdf.setLenient(false);
			return sdf.parse(dateString);
		} catch (ParseException e) {
			throw new DSSException("Unable to parse date " + dateString + " (format:" + format + ")", e);
		}
	}

}
