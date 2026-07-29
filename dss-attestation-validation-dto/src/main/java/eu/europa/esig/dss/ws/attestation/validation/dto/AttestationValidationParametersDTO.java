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
package eu.europa.esig.dss.ws.attestation.validation.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;

/**
 * DTO for supplementary attestation validation data parameters
 */
public class AttestationValidationParametersDTO {

    /**
     * Represents SessionTranscript data structure used for generation of Mdoc's deviceAuth (key binding) signature
     */
    private RemoteDocument sessionTranscript;

    /**
     * Empty constructor
     */
    public AttestationValidationParametersDTO() {
        // empty
    }

    /**
     * Constructor with SessionTranscript provided
     *
     * @param sessionTranscript {@link RemoteDocument}
     */
    public AttestationValidationParametersDTO(RemoteDocument sessionTranscript) {
        this.sessionTranscript = sessionTranscript;
    }

    /**
     * Gets SessionTranscript
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getSessionTranscript() {
        return sessionTranscript;
    }

    /**
     * Sets SessionTranscript data structure used for generation of Mdoc's deviceAuth (key binding) signature
     *
     * @param sessionTranscript {@link RemoteDocument}
     */
    public void setSessionTranscript(RemoteDocument sessionTranscript) {
        this.sessionTranscript = sessionTranscript;
    }

}
