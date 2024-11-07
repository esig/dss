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
package eu.europa.esig.dss.enumerations;

/**
 * Defines available types of a SignerRole element
 */
public enum EndorsementType {

	/** Attributes certified in attribute certificates issued by an Attribute Authority */
	CERTIFIED("certified"),

	/** Attributes claimed by the signer */
	CLAIMED("claimed"),

	/** Assertions signed by a third party */
	SIGNED("signed");
	
	private final String value;
	
	EndorsementType(String value) {
		this.value = value;
	}

	/**
	 * Returns the string value of the enumeration
	 *
	 * @return {@link String}
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Parses the string value and returns the {@code EndorsementType}
	 *
	 * @param value {@link String} representing the {@link EndorsementType}
	 * @return {@link EndorsementType} if the values has been parsed successfully, null otherwise
	 */
	public static EndorsementType fromString(String value) {
		for (EndorsementType endorsement : values()) {
			if (endorsement.value.equals(value)) {
				return endorsement;
			}
		}
		return null;
	}

}
