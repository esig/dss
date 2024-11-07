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
package eu.europa.esig.dss.jaxb.parsers;

import jakarta.xml.bind.annotation.adapters.XmlAdapter;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Parses a date
 */
public final class DateParser extends XmlAdapter<String, Date> {

	/** Default used date format */
	private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	/** The default timezone (UTC) */
	private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

	/**
	 * Default constructor
	 */
	public DateParser() {
		// empty
	}

	/**
	 * Parses the date
	 *
	 * @param s {@link String} date in the format "yyyy-MM-dd'T'HH:mm:ss'Z'"
	 * @return {@link Date}, null if not able to parse
	 */
	@Override
	public Date unmarshal(String s) throws Exception {
		if (s == null) {
			return null;
		}
		try {
			SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
			sdf.setTimeZone(UTC);
			sdf.setLenient(false);
			return sdf.parse(s);
		} catch (Exception e) {
			throw new IllegalArgumentException(String.format("String '%s' doesn't follow the pattern '%s'", s, DATE_FORMAT));
		}
	}

	/**
	 * Prints the date according to the format "yyyy-MM-dd'T'HH:mm:ss'Z'"
	 *
	 * @param date {@link Date}
	 * @return {@link String}
	 */
	@Override
	public String marshal(Date date) throws Exception {
		if (date != null) {
			SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
			sdf.setTimeZone(UTC);
			return sdf.format(date);
		}
		return null;
	}

}
