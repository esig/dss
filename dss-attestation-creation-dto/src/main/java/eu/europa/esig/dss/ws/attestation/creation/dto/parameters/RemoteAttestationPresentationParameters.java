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

import eu.europa.esig.dss.enumerations.AttestationFormat;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * DTO containing parameters for Attestation Presentation issuance
 *
 */
public class RemoteAttestationPresentationParameters implements Serializable {

    private static final long serialVersionUID = 9020368962150645764L;

    /** (Required) Type of the EAA to be created */
    private AttestationFormat attestationFormat;

    /* Mdoc parameters */

    /** The list of device signed data elements */
    private List<ClaimDTO> deviceSignedDataElements;

    /**
     * Default constructor
     */
    public RemoteAttestationPresentationParameters() {
        super();
    }

    /**
     * Constructor with EAA type provided
     *
     * @param attestationFormat {@link AttestationFormat}
     */
    public RemoteAttestationPresentationParameters(AttestationFormat attestationFormat) {
        this.attestationFormat = attestationFormat;
    }

    /**
     * Gets the EAA Type
     *
     * @return {@link AttestationFormat}
     */
    public AttestationFormat getEaaType() {
        return attestationFormat;
    }

    /**
     * Sets the target EAA type
     *
     * @param attestationFormat {@link AttestationFormat}
     */
    public void setEaaType(AttestationFormat attestationFormat) {
        this.attestationFormat = attestationFormat;
    }

    /**
     * Gets the list of device signed data elements
     *
     * @return {@link List<ClaimDTO>}
     */
    public List<ClaimDTO> getDeviceSignedDataElements() {
        return deviceSignedDataElements;
    }

    /**
     * (Mdoc) Sets the list of device signed data elements
     *
     * @param deviceSignedDataElements {@link List<ClaimDTO>}
     */
    public void setDeviceSignedDataElements(final List<ClaimDTO> deviceSignedDataElements) {
        this.deviceSignedDataElements = deviceSignedDataElements;
    }

    @Override
    public String toString() {
        return "RemoteEAAPresentationParameters [" +
                "eaaType=" + attestationFormat +
                ", deviceSignedDataElements=" + deviceSignedDataElements +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        RemoteAttestationPresentationParameters that = (RemoteAttestationPresentationParameters) object;
        return attestationFormat == that.attestationFormat
                && Objects.equals(deviceSignedDataElements, that.deviceSignedDataElements);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(attestationFormat);
        result = 31 * result + Objects.hashCode(deviceSignedDataElements);
        return result;
    }

}
