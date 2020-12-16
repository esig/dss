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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.validation.ReferenceValidation;

import java.util.ArrayList;
import java.util.List;

/**
 * The JAdES reference validation result
 */
public class JAdESReferenceValidation extends ReferenceValidation {
	
	private static final long serialVersionUID = 2819574054512130987L;

	/** List of errors occurred during the reference validation */
	private List<String> errorMessages = new ArrayList<>();

	/**
	 * Gets error messages occurred during the reference validation
	 *
	 * @return a list of {@link String} messages
	 */
	public List<String> getErrorMessages() {
		return errorMessages;
	}

	/**
	 * Sets error messages occurred during the reference validation
	 *
	 * @param errorMessages a list of {@link String} messages
	 */
	public void setErrorMessages(List<String> errorMessages) {
		this.errorMessages = errorMessages;
	}

}
