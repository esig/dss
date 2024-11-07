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
package eu.europa.esig.dss.model.signature;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents the information concerning the signature production place.
 *
 */
@SuppressWarnings("serial")
public class SignatureProductionPlace implements Serializable {

	/** The location (city) */
	private String city;

	/** The region (stateOrProvince) */
	private String stateOrProvince;

	/** The postOfficeBoxNumber */
	private String postOfficeBoxNumber;

	/** The postalCode */
	private String postalCode;

	/** The countryName (can be 2-letters abbreviation, e.g. LU for Luxembourg) */
	private String countryName;

	/** The address */
	private String streetAddress;

	/** The postal address (used in CAdES) */
	private List<String> postalAddress;

	/**
	 * Default constructor instantiating object with null values
	 */
	public SignatureProductionPlace() {
		// empty
	}

	/**
	 * Gets location (city)
	 *
	 * @return {@link String}
	 */
	public String getCity() {
		return city;
	}

	/**
	 * Sets location (city)
	 *
	 * @param city {@link String}
	 */
	public void setCity(String city) {
		this.city = city;
	}

	/**
	 * Gets region (stateOrProvince)
	 *
	 * @return {@link String}
	 */
	public String getStateOrProvince() {
		return stateOrProvince;
	}

	/**
	 * Sets region (stateOrProvince)
	 *
	 * @param stateOrProvince {@link String}
	 */
	public void setStateOrProvince(String stateOrProvince) {
		this.stateOrProvince = stateOrProvince;
	}

	/**
	 * Gets postOfficeBoxNumber
	 *
	 * @return {@link String}
	 */
	public String getPostOfficeBoxNumber() {
		return postOfficeBoxNumber;
	}

	/**
	 * Sets postOfficeBoxNumber
	 *
	 * @param postOfficeBoxNumber {@link String}
	 */
	public void setPostOfficeBoxNumber(String postOfficeBoxNumber) {
		this.postOfficeBoxNumber = postOfficeBoxNumber;
	}

	/**
	 * Gets postal code
	 *
	 * @return {@link String}
	 */
	public String getPostalCode() {
		return postalCode;
	}

	/**
	 * Sets postal code
	 *
	 * @param postalCode {@link String}
	 */
	public void setPostalCode(String postalCode) {
		this.postalCode = postalCode;
	}

	/**
	 * Gets country name
	 *
	 * @return {@link String}
	 */
	public String getCountryName() {
		return countryName;
	}

	/**
	 * Sets country name (can be 2-letters abbreviation, e.g. LU for Luxembourg)
	 *
	 * @param countryName {@link String}
	 */
	public void setCountryName(String countryName) {
		this.countryName = countryName;
	}

	/**
	 * Gets the address
	 *
	 * @return {@link String}
	 */
	public String getStreetAddress() {
		return streetAddress;
	}

	/**
	 * Sets the address
	 *
	 * @param streetAddress {@link String}
	 */
	public void setStreetAddress(String streetAddress) {
		this.streetAddress = streetAddress;
	}

	/**
	 * Gets postal address (used in CAdES)
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getPostalAddress() {
		if (postalAddress == null) {
			postalAddress = new ArrayList<>();
		}
		return postalAddress;
	}

	/**
	 * Sets postal address (used in CAdES)
	 *
	 * @param postalAddress a list of {@link String}s
	 */
	public void setPostalAddress(List<String> postalAddress) {
		this.postalAddress = postalAddress;
	}

}
