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

import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationParsingParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

/**
 * Data-transfer-object for a #parseAttestation method configuration
 *
 */
public class ParseAttestationDTO {

    /** Attestation document */
    private RemoteDocument attestation;

    /** Parameters for attestation parsing */
    private RemoteAttestationParsingParameters attestationParsingParameters;

    /**
     * Empty constructor
     */
    public ParseAttestationDTO() {
        // empty
    }

    /**
     * Constructor with attestation and parsing parameters provided
     *
     * @param attestation {@link RemoteDocument} to be parsed
     * @param attestationParsingParameters {@link RemoteAttestationParsingParameters}
     */
    public ParseAttestationDTO(RemoteDocument attestation, RemoteAttestationParsingParameters attestationParsingParameters) {
        this.attestation = attestation;
        this.attestationParsingParameters = attestationParsingParameters;
    }

    /**
     * Gets the signed attestation document
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getAttestation() {
        return attestation;
    }

    /**
     * Sets a signed attestation document
     *
     * @param attestation {@link RemoteDocument}
     */
    public void setAttestation(RemoteDocument attestation) {
        this.attestation = attestation;
    }

    /**
     * Gets the attestation parsing parameters
     *
     * @return {@link RemoteAttestationParsingParameters}
     */
    public RemoteAttestationParsingParameters getAttestationParsingParameters() {
        return attestationParsingParameters;
    }

    /**
     * Sets the attestation parsing parameters
     *
     * @param attestationParsingParameters {@link RemoteAttestationParsingParameters}
     */
    public void setAttestationParsingParameters(RemoteAttestationParsingParameters attestationParsingParameters) {
        this.attestationParsingParameters = attestationParsingParameters;
    }

}
