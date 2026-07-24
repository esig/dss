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
package eu.europa.esig.dss.ws.eaa.creation.dto.parameters;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import java.io.Serializable;
import java.util.Objects;

/**
 * DTO representing a Token Status List claim
 *
 */
public class RemoteTokenStatusList implements Serializable {

    private static final long serialVersionUID = -3496834119406272264L;

    /** Non-negative integer representing the index check for status information in the Status List */
    private Integer index;

    /** String value that identifies the Status List Token containing the status information */
    private String uri;

    /** Certificate containing the public key that signed or sealed the top-level certificate in the MSO revocation list structure */
    private RemoteCertificate certificate;

    /** Type of the EAA status (ETSI specification only) */
    private String type;

    /** Purpose of the EAA status (ETSI specification only) */
    private String purpose;

    /**
     * Default constructor
     */
    public RemoteTokenStatusList() {
        // empty
    }

    /**
     * Constructor with index and uri provided
     *
     * @param index {@link Integer}
     * @param uri {@link String}
     */
    public RemoteTokenStatusList(Integer index, String uri) {
        this(index, uri, null);
    }

    /**
     * Constructor with index, uri and certificate provided
     *
     * @param index {@link Integer}
     * @param uri {@link String}
     * @param certificate {@link RemoteCertificate}
     */
    public RemoteTokenStatusList(Integer index, String uri, RemoteCertificate certificate) {
        this.index = index;
        this.uri = uri;
        this.certificate = certificate;
    }

    /**
     * Constructor with type, purpose index and uri provided (ETSI TS 119 472-1 v1.2.1 definition)
     *
     * @param type {@link String}
     * @param purpose {@link String}
     * @param index {@link Integer}
     * @param uri {@link String}
     */
    public RemoteTokenStatusList(String type, String purpose, Integer index, String uri) {
        this.type = type;
        this.purpose = purpose;
        this.index = index;
        this.uri = uri;
    }
    /**
     * Returns the EAA index
     *
     * @return the EAA index
     */
    public Integer getIndex() {
        return index;
    }

    /**
     * Sets the EAA index
     *
     * @param index the EAA index to set
     */
    public void setIndex(Integer index) {
        this.index = index;
    }

    /**
     * Returns the URI
     *
     * @return the URI
     */
    public String getUri() {
        return uri;
    }

    /**
     * Sets the URI
     *
     * @param uri the URI to set
     */
    public void setUri(String uri) {
        this.uri = uri;
    }

    /**
     * Returns the certificate
     *
     * @return the certificate
     */
    public RemoteCertificate getCertificate() {
        return certificate;
    }

    /**
     * Sets the certificate
     *
     * @param certificate the certificate to set
     */
    public void setCertificate(RemoteCertificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Returns the type
     *
     * @return the type
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the type
     *
     * @param type the type to set
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Returns the purpose
     *
     * @return the purpose
     */
    public String getPurpose() {
        return purpose;
    }

    /**
     * Sets the purpose
     *
     * @param purpose the purpose to set
     */
    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    @Override
    public String toString() {
        return "RemoteEAAStatusList [" +
                "index=" + index +
                ", uri='" + uri + '\'' +
                ", certificate=" + certificate +
                ", type='" + type + '\'' +
                ", purpose='" + purpose + '\'' +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        RemoteTokenStatusList that = (RemoteTokenStatusList) object;
        return Objects.equals(index, that.index)
                && Objects.equals(uri, that.uri)
                && Objects.equals(certificate, that.certificate)
                && Objects.equals(type, that.type)
                && Objects.equals(purpose, that.purpose);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(index);
        result = 31 * result + Objects.hashCode(uri);
        result = 31 * result + Objects.hashCode(certificate);
        result = 31 * result + Objects.hashCode(type);
        result = 31 * result + Objects.hashCode(purpose);
        return result;
    }

}
