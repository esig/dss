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

import eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationSDCreationService;
import eu.europa.esig.dss.ws.attestation.creation.dto.DisclosuresDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssueAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.soap.client.SoapAttestationSDCreationService;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

/**
 * SOAP implementation of the remote attestation with selective disclosures creation service
 *
 */
public class SoapAttestationSDCreationServiceImpl extends SoapAttestationCreationServiceImpl implements SoapAttestationSDCreationService {

    private static final long serialVersionUID = -5824362174327062129L;

    /**
     * Default constructor
     */
    public SoapAttestationSDCreationServiceImpl() {
        // empty
    }

    @Override
    protected RemoteAttestationSDCreationService getService() {
        return (RemoteAttestationSDCreationService) super.getService();
    }

    @Override
    public List<DisclosureDTO> generateDisclosures(DisclosuresDTO disclosuresDTO) {
        return getService().generateDisclosures(disclosuresDTO.getPayloadParameters());
    }

    @Override
    public RemoteDocument issueAttestation(IssueAttestationDTO issueAttestationDTO) {
        return getService().issueAttestation(issueAttestationDTO.getSignedAttestation(),
                issueAttestationDTO.getPayloadParameters(), issueAttestationDTO.getDisclosures());
    }

}
