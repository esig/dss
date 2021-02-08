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
import java.util.List;

public class XSDValidationException extends RuntimeException {

	private static final long serialVersionUID = 4928003472348809475L;

	private final List<String> exceptionMessages;

	public XSDValidationException(List<String> exceptionMessages) {
		super();
		this.exceptionMessages = exceptionMessages;
	}

	public List<String> getAllMessages() {
		if (exceptionMessages == null) {
			return Collections.emptyList();
		}
		return exceptionMessages;
	}

	@Override
	public String getMessage() {
		List<String> allMessages = getAllMessages();
		if (allMessages != null && allMessages.size() > 0) {
			return allMessages.toString();
		}
		return null;
	}

}
