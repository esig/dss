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
package eu.europa.esig.dss.ws.attestation.creation.soap.client;

import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.SignAttestationDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

import java.io.Serializable;

/**
 * This SOAP interface provides operations for the signing of an attestation.
 *
 */
@WebService(targetNamespace = "http://attestation.creation.dss.esig.europa.eu/")
public interface SoapAttestationCreationService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed based on the {@code payload} and {@code parameters}.
     *
     * @param dataToSignAttestationDTO {@link DataToSignAttestationDTO} a DTO with the needed
     *                         information (payload and signature parameters) to compute the data
     *                         to be signed
     * @return the data to be signed
     */
    @WebResult(name = "response")
    ToBeSignedDTO getDataToSign(@WebParam(name = "dataToSignAttestationDTO") final DataToSignAttestationDTO dataToSignAttestationDTO);

    /**
     * Signs the attestation with the provided signatureValue.
     *
     * @param signAttestationDTO {@link SignAttestationDTO} a DTO with the needed
     *                   information (payload and signature parameters, signature value) to
     *                   generate the signed attestation
     * @return the signed document (signature signing the attestation)
     */
    @WebResult(name = "response")
    RemoteDocument signAttestation(@WebParam(name = "signAttestationDTO") final SignAttestationDTO signAttestationDTO);

}
