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
package eu.europa.esig.dss.jaxb.common.exception;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * An exception to be thrown in case of XSD validation error(s)
 *
 */
public class XSDValidationException extends RuntimeException {

	private static final long serialVersionUID = 4928003472348809475L;

	/** A list of XSD validation error messages */
	private final List<String> exceptionMessages;

	/**
	 * Default constructor
	 *
	 * @param exceptionMessages a list of {@link String} XSD validation error messages
	 */
	public XSDValidationException(List<String> exceptionMessages) {
		super();
		this.exceptionMessages = exceptionMessages;
	}

	/**
	 * Returns the XSD validation error messages
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getAllMessages() {
		if (exceptionMessages == null) {
			return Collections.emptyList();
		}
		return exceptionMessages;
	}

	@Override
	public String getMessage() {
		List<String> allMessages = getAllMessages();
		if (allMessages != null && !allMessages.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			Iterator<String> it = allMessages.iterator();
			while (it.hasNext()) {
				String message = it.next();
				sb.append(message);
				if (it.hasNext()) {
					sb.append("; ");
				}
			}
			return sb.toString();
		}
		return null;
	}

}
