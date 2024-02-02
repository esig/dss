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
package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.List;

/**
 * Represents an Evidence Record's ArchiveTimeStamp object.
 * Contains the hash tree as well as the time-stamp binaries.
 */
public class ArchiveTimeStampObject implements EvidenceRecordObject {

    private static final long serialVersionUID = 5881635666028328980L;

    /** The ordered list of data object groups containing their digest values */
    private List<? extends DigestValueGroup> hashTree;

    /** Time-stamp token */
    private TimestampToken timestampToken;

    /** Contains validation information for the timestampToken */
    private List<CryptographicInformation> cryptographicInformationList;

    /** Order of the element */
    private int order;

    /**
     * Default constructor
     */
    public ArchiveTimeStampObject() {
        // empty
    }

    /**
     * Gets the ordered hash tree
     *
     * @return a list of {@link DigestValueGroup}s
     */
    public List<? extends DigestValueGroup> getHashTree() {
        return hashTree;
    }

    /**
     * Sets the ordered hash tree
     *
     * @param hashTree a list of {@link DigestValueGroup}s
     */
    public void setHashTree(List<? extends DigestValueGroup> hashTree) {
        this.hashTree = hashTree;
    }

    /**
     * Gets the time-stamp
     *
     * @return {@link TimestampToken}
     */
    public TimestampToken getTimestampToken() {
        return timestampToken;
    }

    /**
     * Sets the time-stamp token
     *
     * @param timestampToken {@link TimestampToken}
     */
    public void setTimestampToken(TimestampToken timestampToken) {
        this.timestampToken = timestampToken;
    }

    /**
     * Gets cryptographic information list
     *
     * @return a list of {@link CryptographicInformation}s
     */
    public List<CryptographicInformation> getCryptographicInformationList() {
        return cryptographicInformationList;
    }

    /**
     * Sets cryptographic information list
     *
     * @param cryptographicInformationList a list of {@link CryptographicInformation}s
     */
    public void setCryptographicInformationList(List<CryptographicInformation> cryptographicInformationList) {
        this.cryptographicInformationList = cryptographicInformationList;
    }

    /**
     * Gets Order attribute value of the corresponding element
     *
     * @return Order attribute value
     */
    public int getOrder() {
        return order;
    }

    /**
     * Sets order of the object within its parent
     *
     * @param order int value
     */
    public void setOrder(int order) {
        this.order = order;
    }

}
