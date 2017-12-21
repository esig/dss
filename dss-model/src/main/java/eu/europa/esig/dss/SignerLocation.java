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
package eu.europa.esig.dss;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("serial")
public class SignerLocation implements Serializable {

	private List<String> postalAddress = new ArrayList<String>();
	private String postalCode;
	private String locality;
	private String stateOrProvince;
	private String country;
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
			postalAddress = new ArrayList<String>();
		}
		postalAddress.add(addressItem);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((country == null) ? 0 : country.hashCode());
		result = (prime * result) + ((locality == null) ? 0 : locality.hashCode());
		result = (prime * result) + ((postalAddress == null) ? 0 : postalAddress.hashCode());
		result = (prime * result) + ((postalCode == null) ? 0 : postalCode.hashCode());
		result = (prime * result) + ((stateOrProvince == null) ? 0 : stateOrProvince.hashCode());
		result = (prime * result) + ((street == null) ? 0 : street.hashCode());
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
		if (country == null) {
			if (other.country != null) {
				return false;
			}
		} else if (!country.equals(other.country)) {
			return false;
		}
		if (locality == null) {
			if (other.locality != null) {
				return false;
			}
		} else if (!locality.equals(other.locality)) {
			return false;
		}
		if (postalAddress == null) {
			if (other.postalAddress != null) {
				return false;
			}
		} else if (!postalAddress.equals(other.postalAddress)) {
			return false;
		}
		if (postalCode == null) {
			if (other.postalCode != null) {
				return false;
			}
		} else if (!postalCode.equals(other.postalCode)) {
			return false;
		}
		if (stateOrProvince == null) {
			if (other.stateOrProvince != null) {
				return false;
			}
		} else if (!stateOrProvince.equals(other.stateOrProvince)) {
			return false;
		}
		if (street == null) {
			if (other.street != null) {
				return false;
			}
		} else if (!street.equals(other.street)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "SignerLocation [postalAddress=" + postalAddress + ", postalCode=" + postalCode + ", locality=" + locality + ", stateOrProvince="
				+ stateOrProvince + ", country=" + country + ", street=" + street + "]";
	}

}
