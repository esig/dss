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
package eu.europa.esig.dss.spi.exception;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Contains a map of occurred exceptions to different URL calls
 */
public class DSSDataLoaderMultipleException extends DSSExternalResourceException {

	private static final long serialVersionUID = 4981228392826668216L;

	/** A map between failed URLs and caused exceptions */
	private final Map<String, Throwable> urlExceptionMap;

	/**
	 * Default constructor
	 *
	 * @param urlExceptionMap a map between failed URLs and caused exceptions
	 */
	public DSSDataLoaderMultipleException(Map<String, Throwable> urlExceptionMap) {
		this.urlExceptionMap = urlExceptionMap;
	}
	
	@Override
	public String getMessage() {
		StringBuilder stringBuilder = new StringBuilder();
		for (Map.Entry<String, Throwable> exceptionEntry : urlExceptionMap.entrySet()) {
			Throwable exception = exceptionEntry.getValue();
			String errorMessage = exception.getMessage();
			if (exception instanceof DSSExternalResourceException) {
				errorMessage = ((DSSExternalResourceException) exception).getCauseMessage();
			}
			stringBuilder.append("Failed to get data from URL '").append(exceptionEntry.getKey()).append("'. Reason : ");
			stringBuilder.append('[').append(errorMessage).append("]. ");
		}
		return stringBuilder.toString();
	}
	
	@Override
	public StackTraceElement[] getStackTrace() {
		List<StackTraceElement> stackTraceElements = new ArrayList<>();
		for (Throwable exception : urlExceptionMap.values()) {
			stackTraceElements.addAll(Arrays.asList(exception.getStackTrace()));
		}
		return stackTraceElements.toArray(new StackTraceElement[stackTraceElements.size()]);
	}
	
	@Override
	String getCauseMessage() {
		return getMessage();
	}

}
