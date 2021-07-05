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
package eu.europa.esig.dss.jaxb.parsers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Parses a date
 */
public final class DateParser {

	private static final Logger LOG = LoggerFactory.getLogger(DateParser.class);

	/** Default used date format */
	private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	/** The default timezone (UTC) */
	private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

	private DateParser() {
	}

	/**
	 * Parses the date
	 *
	 * @param v {@link String} date in the format "yyyy-MM-dd'T'HH:mm:ss'Z'"
	 * @return {@link Date}, null if not able to parse
	 */
	public static Date parse(String v) {
		if (v == null) {
			return null;
		}
		try {
			SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
			sdf.setTimeZone(UTC);
			sdf.setLenient(false);
			return sdf.parse(v);
		} catch (Exception e) {
			throw new IllegalArgumentException(String.format("String '%s' doesn't follow the pattern '%s'", v, DATE_FORMAT));
		}
	}

	/**
	 * Prints the date according to the format "yyyy-MM-dd'T'HH:mm:ss'Z'"
	 *
	 * @param v {@link Date}
	 * @return {@link String}
	 */
	public static String print(Date v) {
		if (v != null) {
			SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
			sdf.setTimeZone(UTC);
			return sdf.format(v);
		}
		return null;
	}

}