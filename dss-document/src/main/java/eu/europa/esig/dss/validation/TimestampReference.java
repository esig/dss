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
package eu.europa.esig.dss.validation;

import org.apache.commons.codec.binary.Base64;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * This class stocks the timestamp reference, which is composed of:
 * - digest algorithm used to calculate the digest value of the reference;
 * - digest value of the reference;
 * - the timestamp reference category {@code TimestampReferenceCategory};
 * - signature id in the case where the reference apply to the signature.
 */
public class TimestampReference {

	private String signatureId;

	private String digestAlgorithm;
	private String digestValue;
	private TimestampReferenceCategory category;

	public TimestampReference(final String signatureId) {

		if (signatureId == null) {
			throw new NullPointerException();
		}
		this.signatureId = signatureId;
		this.digestAlgorithm = DigestAlgorithm.SHA1.name();
		this.digestValue = Base64.encodeBase64String(DSSUtils.digest(DigestAlgorithm.SHA1, signatureId.getBytes()));
		this.category = TimestampReferenceCategory.SIGNATURE;
	}

	public TimestampReference(final String digestAlgorithm, final String digestValue) {

		if (digestAlgorithm == null) {
			throw new NullPointerException("digestAlgorithm");
		}
		this.digestAlgorithm = digestAlgorithm;
		if (digestValue == null) {
			throw new NullPointerException("digestValue");
		}
		this.digestValue = digestValue;
		this.category = TimestampReferenceCategory.CERTIFICATE;
	}

	public TimestampReference(final String digestAlgorithm, final String digestValue, final TimestampReferenceCategory category) {

		this(digestAlgorithm, digestValue);
		this.category = category;
	}

	public String getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public String getDigestValue() {
		return digestValue;
	}

	public TimestampReferenceCategory getCategory() {
		return category;
	}

	public String getSignatureId() {
		return signatureId;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		TimestampReference that = (TimestampReference) o;

		if (!digestValue.equals(that.digestValue)) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		return digestValue.hashCode();
	}
}
