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

/**
 * This class represents a signature Reference element considered for inclusion within a content timestamp
 * (i.e. a XAdES AllDataObjectsTimestamp, or a XAdES IndividualDataObjectsTimestamp).
 */
public class ContentTimestampReference {

    /**
     * The data contained within the Reference element
     */
    private byte[] data;

	/**
	 * The URI of the Reference element
	 */
	private String uri;

	/**
     * Getter for the data attribute
     * @return
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Setter for the data attribute
     * @param data
     */
    public void setData(byte[] data) {
        this.data = data;
    }

	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}
}
