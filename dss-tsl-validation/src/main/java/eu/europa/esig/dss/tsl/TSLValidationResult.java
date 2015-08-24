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
package eu.europa.esig.dss.tsl;

import eu.europa.esig.dss.validation.policy.rules.Indication;

/**
 * This class is a DTO result for TSLValidator Callable.
 */
public class TSLValidationResult {

	private String countryCode;
	private String indication;
	private String subIndication;

	public String getCountryCode() {
		return countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public String getIndication() {
		return indication;
	}

	public void setIndication(String indication) {
		this.indication = indication;
	}

	public String getSubIndication() {
		return subIndication;
	}

	public void setSubIndication(String subIndication) {
		this.subIndication = subIndication;
	}

	public boolean isValid() {
		return Indication.VALID.equals(indication);
	}

	public boolean isIndeterminate() {
		return Indication.INDETERMINATE.equals(indication);
	}

	public boolean isInvalid() {
		return Indication.INVALID.equals(indication);
	}

}
