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

public class CachedException {

	private final Date date = new Date();
	private Date lastOccurrenceDate = new Date();
	private final Exception exception;

	public CachedException(Exception exception) {
		Objects.requireNonNull(exception);
		this.exception = exception;
	}

	public Date getDate() {
		return date;
	}
	
	public Date getLastOccurrenceDate()  {
		return lastOccurrenceDate;
	}
	
	public void setLastOccurrenceDate(Date lastOccurrenceDate) {
		this.lastOccurrenceDate = lastOccurrenceDate;
	}

	public Exception getException() {
		return exception;
	}
	
	public String getExceptionMessage() {
		return exception.getMessage();
	}
	
	public String getStackTrace() {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		exception.printStackTrace(pw);
		return sw.toString();
	}

}
