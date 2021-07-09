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
package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.Serializable;
import java.util.Objects;

/**
 * Parameters for a timestamp creation
 *
 */
@SuppressWarnings("serial")
public class RemoteTimestampParameters implements Serializable {

	/**
	 * The digest algorithm to provide to the timestamping authority
	 */
	private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

	/**
	 * This is the default canonicalization method for XMLDSIG used for timestamps. Another complication arises because
	 * of the way that the default canonicalization algorithm
	 * handles namespace declarations; frequently a signed XML document needs to be embedded in another document; in
	 * this case the original canonicalization algorithm will not
	 * yield the same result as if the document is treated alone. For this reason, the so-called Exclusive
	 * Canonicalization, which serializes XML namespace declarations
	 * independently of the surrounding XML, was created.
	 */
	private String canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;

	/**
	 * Specifies format of the output file containing a timestamp
	 */
	private TimestampContainerForm timestampContainerForm;

	/**
	 * Empty constructor
	 */
	public RemoteTimestampParameters() {
	}

	/**
	 * Default constructor
	 *
	 * @param timestampForm {@link TimestampContainerForm}
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 */
	public RemoteTimestampParameters(TimestampContainerForm timestampForm, DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
		this.timestampContainerForm = timestampForm;
	}

	/**
	 * Constructor with a canonicalization method (to be used for XAdES)
	 *
	 * @param timestampForm {@link TimestampContainerForm}
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param canonicalizationMethod {@link String}
	 */
	public RemoteTimestampParameters(TimestampContainerForm timestampForm, DigestAlgorithm digestAlgorithm,
									 String canonicalizationMethod) {
		this(timestampForm, digestAlgorithm);
		this.canonicalizationMethod = canonicalizationMethod;
	}

	/**
	 * Gets the digest algorithm
	 *
	 * @return {@link DigestAlgorithm}
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * Sets the digest algorithm for message-imprint hash computation
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 */
	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestAlgorithm, "digestAlgorithm must be specified!");
		this.digestAlgorithm = digestAlgorithm;
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
	 * Sets the canonicalization algorithm
	 *
	 * NOTE: to be used for XAdES format only
	 *
	 * @param canonicalizationMethod {@link String}
	 */
	public void setCanonicalizationMethod(final String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	/**
	 * Gets the timestamp container form
	 *
	 * @return {@link TimestampContainerForm}
	 */
	public TimestampContainerForm getTimestampContainerForm() {
		return timestampContainerForm;
	}

	/**
	 * Sets the timestamp container form for a standalone timestamp creation
	 *
	 * @param timestampForm {@link TimestampContainerForm}
	 */
	public void setTimestampContainerForm(TimestampContainerForm timestampForm) {
		this.timestampContainerForm = timestampForm;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
		result = (prime * result) + ((timestampContainerForm == null) ? 0 : timestampContainerForm.hashCode());
		result = (prime * result) + ((canonicalizationMethod == null) ? 0 : canonicalizationMethod.hashCode());
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
		RemoteTimestampParameters other = (RemoteTimestampParameters) obj;
		if (canonicalizationMethod == null) {
			if (other.canonicalizationMethod != null) {
				return false;
			}
		} else if (!canonicalizationMethod.equals(other.canonicalizationMethod)) {
			return false;
		}
		if (digestAlgorithm != other.digestAlgorithm) {
			return false;
		}
		if (timestampContainerForm == null) {
			if (other.timestampContainerForm != null) {
				return false;
			}
		} else if (timestampContainerForm != other.timestampContainerForm) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "RemoteTimestampParameters{digestAlgorithm='" + digestAlgorithm + "', canonicalizationMethod='"
				+ canonicalizationMethod + "', timestampContainerForm=" + timestampContainerForm + '}';
	}

}
