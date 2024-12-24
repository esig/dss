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
package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.utils.Utils;

import java.util.Objects;

/**
 * Parameters for a XAdES timestamp creation
 */
@SuppressWarnings("serial")
public class XAdESTimestampParameters extends TimestampParameters {

	/** The canonicalization method to use for the message-imprint */
	private String canonicalizationMethod = XMLCanonicalizer.DEFAULT_DSS_C14N_METHOD;

	/**
	 * Empty constructor
	 */
	public XAdESTimestampParameters() {
		// empty
	}

	/**
	 * Constructor with digest algorithm
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for message-imprint digest calculation
	 */
	public XAdESTimestampParameters(DigestAlgorithm digestAlgorithm) {
		super(digestAlgorithm);
	}

	/**
	 * Default constructor
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for message-imprint digest calculation
	 * @param canonicalizationMethod {@link String} canonicalization to use for the message-imprint
	 */
	public XAdESTimestampParameters(DigestAlgorithm digestAlgorithm, String canonicalizationMethod) {
		super(digestAlgorithm);
		this.canonicalizationMethod = canonicalizationMethod;
	}

	/**
	 * Gets the canonicalization method
	 *
	 * @return {@link String}
	 */
	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	/**
	 * Sets the canonicalization method
	 *
	 * @param canonicalizationMethod {@link String}
	 */
	public void setCanonicalizationMethod(final String canonicalizationMethod) {
		if (Utils.isStringEmpty(canonicalizationMethod)) {
			throw new IllegalArgumentException("Canonicalization cannot be empty! See EN 319 132-1: 4.5 Managing canonicalization of XML nodesets.");
		}
		this.canonicalizationMethod = canonicalizationMethod;
	}

	@Override
	public String toString() {
		return "XAdESTimestampParameters [" +
				"canonicalizationMethod='" + canonicalizationMethod + '\'' +
				"] " + super.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;

		XAdESTimestampParameters that = (XAdESTimestampParameters) o;
		return Objects.equals(canonicalizationMethod, that.canonicalizationMethod);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Objects.hashCode(canonicalizationMethod);
		return result;
	}

}
