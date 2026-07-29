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
import eu.europa.esig.dss.ws.signature.dto.AbstractDataToSignDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Objects;

/**
 * DTO representing an input data for a getDataToSign method for attestation creation.
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation).
 *
 */
public class DataToSignAttestationDTO extends AbstractDataToSignDTO {

    private static final long serialVersionUID = 965643473429520606L;

    /** The attestation payload parameters */
    private RemoteAttestationPayloadParameters payloadParameters;

    /**
     * Empty constructor
     */
    public DataToSignAttestationDTO() {
        super(null);
    }

    /**
     * Default constructor
     *
     * @param payloadParameters {@link RemoteAttestationPayloadParameters}
     * @param parameters {@link RemoteSignatureParameters}
     */
    public DataToSignAttestationDTO(RemoteAttestationPayloadParameters payloadParameters, RemoteSignatureParameters parameters) {
        super(parameters);
        this.payloadParameters = payloadParameters;
    }

    /**
     * Gets the payload parameters
     *
     * @return {@link RemoteAttestationPayloadParameters}
     */
    public RemoteAttestationPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    /**
     * Sets a payload parameters
     *
     * @param payloadParameters {@link RemoteAttestationPayloadParameters}
     */
    public void setPayloadParameters(RemoteAttestationPayloadParameters payloadParameters) {
        this.payloadParameters = payloadParameters;
    }

    @Override
    public String toString() {
        return "DataToSignAttestationDTO [" +
                "payloadParameters=" + payloadParameters +
                "] " + super.toString();
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;

        DataToSignAttestationDTO that = (DataToSignAttestationDTO) object;
        return Objects.equals(payloadParameters, that.payloadParameters);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Objects.hashCode(payloadParameters);
        return result;
    }

}
