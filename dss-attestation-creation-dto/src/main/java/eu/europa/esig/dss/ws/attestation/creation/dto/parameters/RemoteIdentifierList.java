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
package eu.europa.esig.dss.ws.attestation.creation.dto.parameters;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * DTO representing a Token identifier list
 *
 */
public class RemoteIdentifierList implements Serializable {

    private static final long serialVersionUID = 820595710359956765L;

    /** Byte array representing the index to check for revocation information in the Status List */
    private byte[] identifier;

    /** String value that identifies the Status List Token containing the revocation information */
    private String uri;

    /** (Optional) Certificate containing the public key that signed or sealed the top-level certificate in the MSO revocation list structure */
    private RemoteCertificate certificate;

    /**
     * Default constructor
     */
    public RemoteIdentifierList() {
        // empty
    }

    /**
     * Constructor with index and uri provided
     *
     * @param identifier byte array
     * @param uri {@link String}
     */
    public RemoteIdentifierList(byte[] identifier, String uri) {
        this(identifier, uri, null);
    }

    /**
     * Constructor with index, uri and certificate provided
     *
     * @param identifier byte array
     * @param uri {@link String}
     * @param certificate {@link RemoteCertificate}
     */
    public RemoteIdentifierList(byte[] identifier, String uri, RemoteCertificate certificate) {
        this.identifier = identifier;
        this.uri = uri;
        this.certificate = certificate;
    }

    /**
     * Returns the attestation identifier
     *
     * @return the attestation identifier
     */
    public byte[] getIdentifier() {
        return identifier;
    }

    /**
     * Sets the attestation identifier
     *
     * @param identifier the attestation identifier to set
     */
    public void setIdentifier(byte[] identifier) {
        this.identifier = identifier;
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

    @Override
    public String toString() {
        return "RemoteAttestationIdentifierList [" +
                "identifier=" + Arrays.toString(identifier) +
                ", uri='" + uri + '\'' +
                ", certificate=" + certificate +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        RemoteIdentifierList that = (RemoteIdentifierList) object;
        return Arrays.equals(identifier, that.identifier)
                && Objects.equals(uri, that.uri)
                && Objects.equals(certificate, that.certificate);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(identifier);
        result = 31 * result + Objects.hashCode(uri);
        result = 31 * result + Objects.hashCode(certificate);
        return result;
    }

}
