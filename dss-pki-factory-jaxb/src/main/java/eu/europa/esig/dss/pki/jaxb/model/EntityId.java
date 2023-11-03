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
package eu.europa.esig.dss.pki.jaxb.model;

import eu.europa.esig.dss.pki.jaxb.XmlEntityKey;

/**
 * Represents a deterministic identifier of a certificate entity object
 */
public class EntityId {

    /** The issuer distinguished name */
    private String issuerName;

    /** The certificate's serial number */
    private Long serialNumber;

    /**
     * Empty constructor
     */
    public EntityId() {
        // empty
    }

    /**
     * Default constructor to create a {@code EntityId} based on the provided issuer's DN and certificate's serial number
     *
     * @param issuerName {@link String} issuer's DN
     * @param serialNumber {@link Long} certificate's serial number
     */
    public EntityId(String issuerName, Long serialNumber) {
        this.issuerName = issuerName;
        this.serialNumber = serialNumber;
    }

    /**
     * Constructor to create object from JAXB {@code XmlEntityKey} object of the certificate
     *
     * @param entityKey {@link XmlEntityKey}
     */
    public EntityId(XmlEntityKey entityKey) {
        this(entityKey.getValue(), entityKey.getSerialNumber());
    }

    /**
     * Gets issuer distinguished name
     *
     * @return {@link String}
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * Sets issuer's distinguished name
     *
     * @param issuerName {@link String}
     */
    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * Gets the certificate's serial number
     *
     * @return {@link Long}
     */
    public Long getSerialNumber() {
        return serialNumber;
    }

    /**
     * Sets the certificate's serial number
     *
     * @param serialNumber {@link Long}
     */
    public void setSerialNumber(Long serialNumber) {
        this.serialNumber = serialNumber;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((issuerName == null) ? 0 : issuerName.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        EntityId other = (EntityId) obj;
        if (issuerName == null) {
            if (other.issuerName != null) return false;
        } else if (!issuerName.equals(other.issuerName)) return false;
        if (serialNumber == null) {
            if (other.serialNumber != null) return false;
        } else if (!serialNumber.equals(other.serialNumber)) return false;
        return true;
    }

    @Override
    public String toString() {
        return "EntityId [issuerName=" + issuerName + ", serialNumber=" + serialNumber + "]";
    }

}
