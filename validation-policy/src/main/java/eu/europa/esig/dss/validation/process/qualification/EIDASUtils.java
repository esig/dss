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
package eu.europa.esig.dss.validation.process.qualification;

import javax.xml.bind.DatatypeConverter;
import java.util.Date;

/**
 * Contains EIDAS Utils
 */
public final class EIDASUtils {

	/**
	 * Empty constructor
	 */
	private EIDASUtils() {
	}

	/**
	 * Start date of the eIDAS regulation
	 * 
	 * Regulation was signed in Brussels : 1st of July 00:00 Brussels = 30th of June 22:00 UTC
	 */
	private static final Date EIDAS_DATE = DatatypeConverter.parseDateTime("2016-06-30T22:00:00.000Z").getTime();

	/**
	 * End of the grace period for eIDAS regulation
	 */
	private static final Date EIDAS_GRACE_DATE = DatatypeConverter.parseDateTime("2017-06-30T22:00:00.000Z").getTime();

	/**
	 * Gets if the given date relates to a post eIDAS time
	 *
	 * @param date {@link Date}
	 * @return TRUE if the date is at or after eIDAS
	 */
	public static boolean isPostEIDAS(Date date) {
		return date != null && date.compareTo(EIDAS_DATE) >= 0;
	}

	/**
	 * Gets if the given date relates to a pre eIDAS time
	 *
	 * @param date {@link Date}
	 * @return TRUE if the date is before eIDAS
	 */
	public static boolean isPreEIDAS(Date date) {
		return date != null && date.compareTo(EIDAS_DATE) < 0;
	}

	/**
	 * Gets if the given date relates to a post grace period
	 *
	 * @param date {@link Date}
	 * @return TRUE if the date is at or after grace period
	 */
	public static boolean isPostGracePeriod(Date date) {
		return date != null && date.compareTo(EIDAS_GRACE_DATE) >= 0;
	}

}
