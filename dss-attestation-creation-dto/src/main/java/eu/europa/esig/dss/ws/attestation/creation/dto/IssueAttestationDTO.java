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

import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

/**
 * DTO representing an input data for a issueAttestation method for attestation issuance.
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation).
 *
 */
public class IssueAttestationDTO {

    /** Signed attestation document */
    private RemoteDocument signedAttestation;

    /** Payload parameters */
    private RemoteAttestationPayloadParameters payloadParameters;

    /** Disclosures */
    private List<DisclosureDTO> disclosures;

    /**
     * Empty constructor
     */
    public IssueAttestationDTO() {
        // empty
    }

    /**
     * Constructor to issue attestation based on the payload parameters
     * (selective disclosures are to be generated according to the parameters and included within the attestation).
     *
     * @param signedAttestation {@link RemoteDocument}
     * @param payloadParameters {@link RemoteAttestationPayloadParameters}
     */
    public IssueAttestationDTO(RemoteDocument signedAttestation, RemoteAttestationPayloadParameters payloadParameters) {
        this.signedAttestation = signedAttestation;
        this.payloadParameters = payloadParameters;
    }

    /**
     * Constructor to issue attestation with attached {@code disclosures}
     *
     * @param signedAttestation {@link RemoteDocument}
     * @param attestationForm {@link AttestationForm}
     * @param disclosures a list of {@link DisclosureDTO}s
     */
    public IssueAttestationDTO(RemoteDocument signedAttestation, AttestationForm attestationForm, List<DisclosureDTO> disclosures) {
        this(signedAttestation, new RemoteAttestationPayloadParameters(attestationForm), disclosures);
    }

    /**
     * Constructor to issue attestation with attached {@code disclosures}.
     * NOTE: Parameters are used to define the attestation form, when the method is used.
     *
     * @param signedAttestation {@link RemoteDocument}
     * @param payloadParameters {@link RemoteAttestationPayloadParameters}
     * @param disclosures a list of {@link DisclosureDTO}s
     */
    public IssueAttestationDTO(RemoteDocument signedAttestation, RemoteAttestationPayloadParameters payloadParameters,
                               List<DisclosureDTO> disclosures) {
        this.signedAttestation = signedAttestation;
        this.payloadParameters = payloadParameters;
        this.disclosures = disclosures;
    }

    /**
     * Gets the signed attestation document
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getSignedAttestation() {
        return signedAttestation;
    }

    /**
     * Sets the signed attestation document
     *
     * @param signedAttestation {@link RemoteDocument}
     */
    public void setSignedAttestation(RemoteDocument signedAttestation) {
        this.signedAttestation = signedAttestation;
    }

    /**
     * Gets the payload generation parameters
     *
     * @return {@link RemoteAttestationPayloadParameters}
     */
    public RemoteAttestationPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    /**
     * Sets the payload generation parameters
     *
     * @param payloadParameters {@link RemoteAttestationPayloadParameters}
     */
    public void setPayloadParameters(RemoteAttestationPayloadParameters payloadParameters) {
        this.payloadParameters = payloadParameters;
    }

    /**
     * Gets a list of disclosures to be included to the attestation document
     *
     * @return a list of {@link DisclosureDTO}s
     */
    public List<DisclosureDTO> getDisclosures() {
        return disclosures;
    }

    /**
     * Sets a list of disclosures to be included to the attestation document
     *
     * @param disclosures a list of {@link DisclosureDTO}s
     */
    public void setDisclosures(List<DisclosureDTO> disclosures) {
        this.disclosures = disclosures;
    }

}
