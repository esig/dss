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
package eu.europa.esig.dss.ws.attestation.creation.dto;

import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;

import java.io.Serializable;
import java.util.Objects;

/**
 * DTO representing an input data for a getDisclosures method for EAA creation.
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation).
 *
 */
public class DisclosuresDTO implements Serializable {

    private static final long serialVersionUID = -2112601914515598469L;

    /** Configuration used for the payload computation */
    private RemoteAttestationPayloadParameters payloadParameters;

    /**
     * Default constructor
     */
    public DisclosuresDTO() {
        super();
    }

    /**
     * Constructor with payload parameters
     *
     * @param payloadParameters {@link RemoteAttestationPayloadParameters}
     */
    public DisclosuresDTO(RemoteAttestationPayloadParameters payloadParameters) {
        this.payloadParameters = payloadParameters;
    }

    /**
     * Gets the EAA payload parameters
     *
     * @return {@link RemoteAttestationPayloadParameters}
     */
    public RemoteAttestationPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    /**
     * Sets the EAA payload parameters
     *
     * @param payloadParameters {@link RemoteAttestationPayloadParameters}
     */
    public void setPayloadParameters(RemoteAttestationPayloadParameters payloadParameters) {
        this.payloadParameters = payloadParameters;
    }

    @Override
    public String toString() {
        return "DisclosuresDTO [" +
                "payloadParameters=" + payloadParameters +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        DisclosuresDTO that = (DisclosuresDTO) object;
        return Objects.equals(payloadParameters, that.payloadParameters);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(payloadParameters);
    }

}
