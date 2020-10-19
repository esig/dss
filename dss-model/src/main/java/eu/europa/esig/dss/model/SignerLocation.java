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
package eu.europa.esig.dss.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@SuppressWarnings("serial")
public class SignerLocation implements Serializable {

	/**
	 * A sequence defined a Postal Address
	 * 
	 * NOTE: used in CAdES
	 */
	private List<String> postalAddress = new ArrayList<>();

	/**
	 * The post office box number for PO box addresses.
	 * 
	 * NOTE: used in JAdES
	 */
	private String postOfficeBoxNumber;

	/**
	 * The postal code (ZIP-code). For example, 94043.
	 */
	private String postalCode;

	/**
	 * The locality (city) in which the street address is, and which is in the
	 * region.
	 */
	private String locality;

	/**
	 * State or province. The region in which the locality is, and which is in the
	 * country.
	 */
	private String stateOrProvince;

	/**
	 * The country. For example, USA. You can also provide the two-letter ISO 3166-1
	 * alpha-2 country code.
	 */
	private String country;

	/**
	 * The street address. For example, 1600 Amphitheatre Pkwy.
	 */
	private String street;

	public SignerLocation() {
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(final String country) {
		this.country = country;
	}

	public String getLocality() {
		return locality;
	}

	public void setLocality(final String locality) {
		this.locality = locality;
	}

	public List<String> getPostalAddress() {
		return postalAddress;
	}

	public void setPostalAddress(final List<String> postalAddress) {
		this.postalAddress = postalAddress;
	}

	public String getPostalCode() {
		return postalCode;
	}

	public void setPostalCode(String postalCode) {
		this.postalCode = postalCode;
	}

	public String getPostOfficeBoxNumber() {
		return postOfficeBoxNumber;
	}

	public void setPostOfficeBoxNumber(String postOfficeBoxNumber) {
		this.postOfficeBoxNumber = postOfficeBoxNumber;
	}

	public String getStateOrProvince() {
		return stateOrProvince;
	}

	public void setStateOrProvince(String stateOrProvince) {
		this.stateOrProvince = stateOrProvince;
	}

	public String getStreet() {
		return street;
	}

	public void setStreet(String street) {
		this.street = street;
	}

	/**
	 * Adds an address item to the complete address.
	 *
	 * @param addressItem
	 *            an address line
	 */
	public void addPostalAddress(final String addressItem) {
		if (postalAddress == null) {
			postalAddress = new ArrayList<>();
		}
		postalAddress.add(addressItem);
	}
	
	/**
	 * Checks if the SignerLocation instance is empty
	 * 
	 * @return TRUE if none of the fields are filled in, FALSE otherwise
	 */
	public boolean isEmpty() {
		if (postalAddress != null && !postalAddress.isEmpty()) {
			return false;
		}
		if (postalCode != null && !postalCode.isEmpty()) {
			return false;
		}
		if (postOfficeBoxNumber != null && !postOfficeBoxNumber.isEmpty()) {
			return false;
		}
		if (locality != null && !locality.isEmpty()) {
			return false;
		}
		if (stateOrProvince != null && !stateOrProvince.isEmpty()) {
			return false;
		}
		if (country != null && !country.isEmpty()) {
			return false;
		}
		if (street != null && !street.isEmpty()) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((country == null) ? 0 : country.hashCode());
		result = prime * result + ((locality == null) ? 0 : locality.hashCode());
		result = prime * result + ((postOfficeBoxNumber == null) ? 0 : postOfficeBoxNumber.hashCode());
		result = prime * result + ((postalAddress == null) ? 0 : postalAddress.hashCode());
		result = prime * result + ((postalCode == null) ? 0 : postalCode.hashCode());
		result = prime * result + ((stateOrProvince == null) ? 0 : stateOrProvince.hashCode());
		result = prime * result + ((street == null) ? 0 : street.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SignerLocation other = (SignerLocation) obj;
		if (!Objects.equals(country, other.country)) {
			return false;
		}
		if (!Objects.equals(locality, other.locality)) {
			return false;
		}
		if (!Objects.equals(postOfficeBoxNumber, other.postOfficeBoxNumber)) {
			return false;
		}
		if (!Objects.equals(postalAddress, other.postalAddress)) {
			return false;
		}
		if (!Objects.equals(postalCode, other.postalCode)) {
			return false;
		}
		if (!Objects.equals(stateOrProvince, other.stateOrProvince)) {
			return false;
		}
		if (!Objects.equals(street, other.street)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "SignerLocation [postalAddress=" + postalAddress + ", postOfficeBoxNumber=" + postOfficeBoxNumber
				+ ", postalCode=" + postalCode + ", locality=" + locality + ", stateOrProvince=" + stateOrProvince
				+ ", country=" + country + ", street=" + street + "]";
	}

}
