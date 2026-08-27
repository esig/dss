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

import eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationPresentationService;
import eu.europa.esig.dss.ws.attestation.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.ParseAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.attestation.creation.soap.client.SoapAttestationPresentationService;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;

/**
 * Default implementation of the SOAP attestation presentation service
 *
 */
public class SoapAttestationPresentationServiceImpl implements SoapAttestationPresentationService {

    /** The service to use */
    private RemoteAttestationPresentationService service;

    /**
     * Default construction instantiating object with null SoapAttestationCreationService
     */
    public SoapAttestationPresentationServiceImpl() {
        // empty
    }

    /**
     * Gets the remote attestation presentation service
     *
     * @return {@link RemoteAttestationPresentationService}
     */
    protected RemoteAttestationPresentationService getService() {
        return service;
    }

    /**
     * Sets the remote attestation presentation service
     *
     * @param service {@link RemoteAttestationPresentationService}
     */
    public void setService(RemoteAttestationPresentationService service) {
        this.service = service;
    }

    @Override
    public RemoteAttestationDocument parseAttestation(ParseAttestationDTO parseAttestationDTO) {
        return getService().parseAttestation(parseAttestationDTO.getAttestation(), parseAttestationDTO.getAttestationParsingParameters());
    }

    @Override
    public ToBeSignedDTO getDataToSignForKeyBindingSignature(DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO) {
        return getService().getDataToSignForKeyBindingSignature(dataToSignForKeyBindingSignatureDTO.getSignedAttestation(),
                dataToSignForKeyBindingSignatureDTO.getDisclosures(), dataToSignForKeyBindingSignatureDTO.getKeyBindingParameters(),
                dataToSignForKeyBindingSignatureDTO.getParameters());
    }

    @Override
    public RemoteDocument createKeyBindingSignature(CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO) {
        return getService().createKeyBindingSignature(createKeyBindingSignatureDTO.getSignedAttestation(),
                createKeyBindingSignatureDTO.getDisclosures(), createKeyBindingSignatureDTO.getKeyBindingParameters(),
                createKeyBindingSignatureDTO.getParameters(), createKeyBindingSignatureDTO.getSignatureValue());
    }

    @Override
    public RemoteDocument issuePresentation(IssuePresentationDTO issuePresentationDTO) {
        return getService().issuePresentation(issuePresentationDTO.getAttestation(), issuePresentationDTO.getDisclosures(),
                issuePresentationDTO.getKeyBindingSignature(), issuePresentationDTO.getPresentationParameters());
    }

}
