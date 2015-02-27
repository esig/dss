/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSNullException;

/**
 * This class stocks the timestamp reference, which is composed of:
 * - digest algorithm used to calculate the digest value of the reference;
 * - digest value of the reference;
 * - the timestamp reference category {@code TimestampReferenceCategory};
 * - signature id in the case where the reference apply to the signature.
 *
 * @author bielecro
 */
public class TimestampReference {

	private String signatureId;

	private String digestAlgorithm;
	private String digestValue;
	private TimestampReferenceCategory category;

	public TimestampReference(final String signatureId) {

		if (signatureId == null) {
			throw new DSSNullException(String.class, "signatureId");
		}
		this.signatureId = signatureId;
		this.digestAlgorithm = DigestAlgorithm.SHA1.name();
		this.digestValue = DSSUtils.base64Encode(DSSUtils.digest(DigestAlgorithm.SHA1, signatureId.getBytes()));
		this.category = TimestampReferenceCategory.SIGNATURE;
	}

	public TimestampReference(final String digestAlgorithm, final String digestValue) {

		if (digestAlgorithm == null) {
			throw new DSSNullException(String.class, "digestAlgorithm");
		}
		this.digestAlgorithm = digestAlgorithm;
		if (digestValue == null) {
			throw new DSSNullException(String.class, "digestValue");
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
