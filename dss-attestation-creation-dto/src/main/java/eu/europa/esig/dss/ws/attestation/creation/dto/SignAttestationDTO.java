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


import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.signature.dto.AbstractSignDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Objects;

/**
 * DTO representing an input data for a signEAA method for EAA creation.
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation).
 *
 */
public class SignAttestationDTO extends AbstractSignDocumentDTO {

    private static final long serialVersionUID = 7028088598170070790L;

    /** The EAA payload parameters */
    private RemoteAttestationPayloadParameters payloadParameters;

    /**
     * Empty constructor
     */
    public SignAttestationDTO() {
        super(null, null);
    }

    /**
     * Default constructor
     *
     * @param payloadParameters {@link RemoteAttestationPayloadParameters}
     * @param parameters {@link RemoteSignatureParameters}
     * @param signatureValue {@link SignatureValueDTO}
     */
    public SignAttestationDTO(RemoteAttestationPayloadParameters payloadParameters, RemoteSignatureParameters parameters, SignatureValueDTO signatureValue) {
        super(parameters, signatureValue);
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
        return "SignEAADTO [" +
                "payloadParameters=" + payloadParameters +
                "] " + super.toString();
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;

        SignAttestationDTO that = (SignAttestationDTO) object;
        return Objects.equals(payloadParameters, that.payloadParameters);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Objects.hashCode(payloadParameters);
        return result;
    }

}
