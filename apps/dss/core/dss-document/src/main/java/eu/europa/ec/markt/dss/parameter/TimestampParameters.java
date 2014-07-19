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
package eu.europa.ec.markt.dss.parameter;

import java.util.ArrayList;
import java.util.List;
import eu.europa.ec.markt.dss.DigestAlgorithm;

/**
 * This class represents the parameters provided when generating specific timestamps in a signature, such as an AllDataObjectsTimestamp or an
 * IndividualDataObjectsTimestamp.
 */
public class TimestampParameters {

    private List<ContentTimestampReference> references;

    /**
     * The digest value for the timestamp
     */
    private byte[] digest;

	/**
	 * The digest algorithm to provide to the timestamping authority
	 */
	private DigestAlgorithm digestAlgorithm;
	private String canonicalizationMethod;

	public List<ContentTimestampReference> getReferences() {
        return references;
    }

    public void setReferences(final List<ContentTimestampReference> references) {
        this.references = references;
    }

    public void addReference(final ContentTimestampReference reference) {
        if (references == null) {
            references = new ArrayList<ContentTimestampReference>();
        }
        references.add(reference);
    }

	public byte[] getDigest() {
		return digest;
	}

	public void setDigest(final byte[] digest) {
		this.digest = digest;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	public void setCanonicalizationMethod(String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}
}
