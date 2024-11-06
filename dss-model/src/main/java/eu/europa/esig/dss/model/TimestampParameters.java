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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.util.Objects;

/**
 * This class represents the parameters provided when generating specific timestamps in a signature, such as an
 * AllDataObjectsTimestamp or an
 * IndividualDataObjectsTimestamp.
 */
@SuppressWarnings("serial")
public abstract class TimestampParameters implements SerializableTimestampParameters {

	/**
	 * The digest algorithm to provide to the timestamping authority
	 */
	protected DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA512;

	/**
	 * Empty constructor
	 */
	protected TimestampParameters() {
		// empty
	}

	/**
	 * The default constructor
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for data digest computation
	 */
	protected TimestampParameters(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * Sets DigestAlgorithm to use for timestamped data's digest computation
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 */
	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	public String toString() {
		return "TimestampParameters [" +
				"digestAlgorithm=" + digestAlgorithm +
				']';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		TimestampParameters that = (TimestampParameters) o;
		return digestAlgorithm == that.digestAlgorithm;
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(digestAlgorithm);
	}

}
