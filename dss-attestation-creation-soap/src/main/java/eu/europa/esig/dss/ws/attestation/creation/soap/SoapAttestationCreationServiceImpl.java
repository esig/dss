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
package eu.europa.esig.dss.ws.attestation.creation.soap;

import eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationCreationService;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.SignAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.soap.client.SoapAttestationCreationService;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;

/**
 * SOAP implementation of the remote attestation creation service
 *
 */
public class SoapAttestationCreationServiceImpl implements SoapAttestationCreationService {

    private static final long serialVersionUID = 3799568238390145342L;

    /** The service to use */
    private RemoteAttestationCreationService service;

    /**
     * Default constructor
     */
    public SoapAttestationCreationServiceImpl() {
        // empty
    }

    /**
     * Gets the remote attestation creation service
     *
     * @return {@link RemoteAttestationCreationService}
     */
    protected RemoteAttestationCreationService getService() {
        return service;
    }

    /**
     * Sets the remote attestation creation service
     *
     * @param service {@link RemoteAttestationCreationService}
     */
    public void setService(RemoteAttestationCreationService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(DataToSignAttestationDTO dataToSignAttestationDTO) {
        return getService().getDataToSign(dataToSignAttestationDTO.getPayloadParameters(), dataToSignAttestationDTO.getParameters());
    }

    @Override
    public RemoteDocument signAttestation(SignAttestationDTO signAttestationDTO) {
        return getService().signAttestation(signAttestationDTO.getPayloadParameters(), signAttestationDTO.getParameters(), signAttestationDTO.getSignatureValue());
    }

}
