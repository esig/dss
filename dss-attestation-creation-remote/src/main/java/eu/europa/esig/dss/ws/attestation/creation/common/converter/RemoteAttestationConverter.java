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
package eu.europa.esig.dss.ws.attestation.creation.common.converter;

import eu.europa.esig.dss.attestation.common.creation.AttestationDocument;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Converts a {@code AttestationDocument} to an instance of
 * {@code eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument}
 *
 */
@SuppressWarnings("rawtypes")
public class RemoteAttestationConverter {

    /**
     * Default constructor
     */
    private RemoteAttestationConverter() {
        // empty
    }

    /**
     * Converts an {@code AttestationDocument} to an instance of
     * {@code eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument}
     *
     * @param attestationDocument {@link AttestationDocument} to convert
     * @return {@link RemoteAttestationDocument}
     */
    @SuppressWarnings("unchecked")
    public static RemoteAttestationDocument toRemoteAttestationDocument(AttestationDocument attestationDocument) {
        final RemoteAttestationDocument remoteAttestationDocument = new RemoteAttestationDocument();
        RemoteDocument signedAttestation = RemoteDocumentConverter.toRemoteDocument(attestationDocument.getSignedAttestation());
        remoteAttestationDocument.setSignedAttestation(signedAttestation);
        List<DisclosureDTO> disclosureDTOs = ((List<SelectiveDisclosure>) attestationDocument.getSelectiveDisclosures())
                .stream().map(new DisclosureToDTOConverter()).collect(Collectors.toList());
        remoteAttestationDocument.setDisclosures(disclosureDTOs);
        return remoteAttestationDocument;
    }

}
