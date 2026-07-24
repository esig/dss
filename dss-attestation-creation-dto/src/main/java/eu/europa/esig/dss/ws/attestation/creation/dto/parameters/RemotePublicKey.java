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
 * DTO containing a public key representation
 *
 */
public class RemotePublicKey implements Serializable {

    private static final long serialVersionUID = 5446356296735375771L;

    /** Public key */
    private byte[] publicKey;

    /** X.509 PKI Certificate */
    private RemoteCertificate certificate;

    /**
     * Default constructor
     */
    public RemotePublicKey() {
        // empty
    }

    /**
     * Returns the public key
     *
     * @return the public key
     */
    public byte[] getPublicKey() {
        return publicKey;
    }

    /**
     * Sets the public key
     *
     * @param publicKey the public key to set
     */
    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
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
        return "RemotePublicKey [" +
                "publicKey=" + Arrays.toString(publicKey) +
                ", certificate=" + certificate +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        RemotePublicKey publicKey1 = (RemotePublicKey) object;
        return Arrays.equals(publicKey, publicKey1.publicKey)
                && Objects.equals(certificate, publicKey1.certificate);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(publicKey);
        result = 31 * result + Objects.hashCode(certificate);
        return result;
    }

}
