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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampParameters;

import java.util.Objects;

/**
 * The parameters to create a JAdES timestamp
 */
@SuppressWarnings("serial")
public class JAdESTimestampParameters extends TimestampParameters {
	
	/**
	 * The canonicalization method to use for timestamp's message imprint computation
	 */
	private String canonicalizationMethod;

	/**
	 * Empty constructor
	 */
	public JAdESTimestampParameters() {
		// empty
	}

	/**
	 * The default constructor
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for a message-imprint calculation
	 */
	public JAdESTimestampParameters(DigestAlgorithm digestAlgorithm) {
		super(digestAlgorithm);
	}

	/**
	 * Gets the canonicalization algorithm for the timestamp
	 *
	 * @return {@link String} canonicalization algorithm
	 */
	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	/**
	 * Sets the canonicalization algorithm for the timestamp
	 *
	 * @param canonicalizationMethod {@link String}
	 */
	public void setCanonicalizationMethod(String canonicalizationMethod) {
		throw new UnsupportedOperationException("Canonicalization is not supported in the current version.");
		// TODO : this.canonicalizationMethod = canonicalizationMethod;
	}

	@Override
	public String toString() {
		return "JAdESTimestampParameters [" +
				"canonicalizationMethod='" + canonicalizationMethod + '\'' +
				"] " + super.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;

		JAdESTimestampParameters that = (JAdESTimestampParameters) o;
		return Objects.equals(canonicalizationMethod, that.canonicalizationMethod);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Objects.hashCode(canonicalizationMethod);
		return result;
	}

}
