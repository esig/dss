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
package eu.europa.esig.dss.tsl.cache.state;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.Objects;

/**
 * Wraps an exception for a cache record
 *
 */
public class CachedExceptionWrapper {

	/** The first occurrence date of the exception */
	private final Date date = new Date();

	/** The exception */
	private final Exception exception;

	/** The last occurrence date of the exception */
	private Date lastOccurrenceDate = new Date();

	/**
	 * Default constructor
	 *
	 * @param exception {@link Exception}
	 */
	public CachedExceptionWrapper(Exception exception) {
		Objects.requireNonNull(exception);
		this.exception = exception;
	}

	/**
	 * Gets the first occurrence date of the exception
	 *
	 * @return {@link Date}
	 */
	public Date getDate() {
		return date;
	}

	/**
	 * Gets the last occurrence date of the exception
	 *
	 * @return {@link Date}
	 */
	public Date getLastOccurrenceDate()  {
		return lastOccurrenceDate;
	}

	/**
	 * Sets the last occurrence date of the exception
	 *
	 * @param lastOccurrenceDate {@link Date}
	 */
	public void setLastOccurrenceDate(Date lastOccurrenceDate) {
		this.lastOccurrenceDate = lastOccurrenceDate;
	}

	/**
	 * Gets the exception
	 *
	 * @return {@link Exception}
	 */
	public Exception getException() {
		return exception;
	}

	/**
	 * Gets the exception message
	 *
	 * @return {@link String}
	 */
	public String getExceptionMessage() {
		return exception.getMessage();
	}

	/**
	 * Gets the exception stack trace
	 *
	 * @return {@link String}
	 */
	public String getStackTrace() {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		exception.printStackTrace(pw);
		return sw.toString();
	}

}
