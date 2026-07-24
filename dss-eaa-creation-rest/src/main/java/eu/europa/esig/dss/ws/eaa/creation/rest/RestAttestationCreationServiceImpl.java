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
package eu.europa.esig.dss.ws.eaa.creation.rest;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.eaa.creation.common.RemoteAttestationCreationService;
import eu.europa.esig.dss.ws.eaa.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.DataToSignAttestationDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.DisclosuresDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.SignAttestationDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.eaa.creation.rest.client.RestAttestationCreationService;

import java.util.List;

/**
 * REST implementation of the remote EAA creation service
 *
 */
public class RestAttestationCreationServiceImpl implements RestAttestationCreationService {

    private static final long serialVersionUID = 3799568238390145342L;

    /** The service to use */
    private RemoteAttestationCreationService service;

    /**
     * Default construction instantiating object with null RemoteEAACreationService
     */
    public RestAttestationCreationServiceImpl() {
        // empty
    }

    /**
     * Sets the remote EAA creation service
     *
     * @param service {@link RemoteAttestationCreationService}
     */
    public void setService(RemoteAttestationCreationService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(DataToSignAttestationDTO dataToSignAttestationDTO) {
        return service.getDataToSign(dataToSignAttestationDTO.getPayloadParameters(), dataToSignAttestationDTO.getParameters());
    }

    @Override
    public RemoteDocument signEAA(SignAttestationDTO signAttestationDTO) {
        return service.signEAA(signAttestationDTO.getPayloadParameters(), signAttestationDTO.getParameters(), signAttestationDTO.getSignatureValue());
    }

    @Override
    public List<DisclosureDTO> getDisclosures(DisclosuresDTO disclosuresDTO) {
        return service.getDisclosures(disclosuresDTO.getPayloadParameters());
    }

    @Override
    public ToBeSignedDTO getDataToSignForKeyBindingSignature(DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO) {
        return service.getDataToSignForKeyBindingSignature(dataToSignForKeyBindingSignatureDTO.getEaa(),
                dataToSignForKeyBindingSignatureDTO.getDisclosures(), dataToSignForKeyBindingSignatureDTO.getKeyBindingParameters(),
                dataToSignForKeyBindingSignatureDTO.getParameters());
    }

    @Override
    public RemoteDocument createKeyBindingSignature(CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO) {
        return service.createKeyBindingSignature(createKeyBindingSignatureDTO.getEaa(),
                createKeyBindingSignatureDTO.getDisclosures(), createKeyBindingSignatureDTO.getKeyBindingParameters(),
                createKeyBindingSignatureDTO.getParameters(), createKeyBindingSignatureDTO.getSignatureValue());
    }

    @Override
    public RemoteDocument issuePresentation(IssuePresentationDTO issuePresentationDTO) {
        return service.issuePresentation(issuePresentationDTO.getEaa(), issuePresentationDTO.getDisclosures(),
                issuePresentationDTO.getKeyBindingSignature(), issuePresentationDTO.getPresentationParameters());
    }

}
