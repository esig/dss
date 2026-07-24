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
package eu.europa.esig.dss.ws.eaa.validation.common;

import eu.europa.esig.dss.spi.eaa.AttestationValidationParameters;
import eu.europa.esig.dss.ws.eaa.validation.dto.AttestationValidationParametersDTO;

/**
 * Builds attestation validation parameters
 *
 */
public class RemoteAttestationValidationParametersBuilder {

    /** DTO EAA Validation parameters */
    private final AttestationValidationParametersDTO attestationValidationParametersDTO;

    /**
     * Default constructor
     *
     * @param attestationValidationParametersDTO {@link AttestationValidationParametersDTO}
     */
    public RemoteAttestationValidationParametersBuilder(final AttestationValidationParametersDTO attestationValidationParametersDTO) {
        this.attestationValidationParametersDTO = attestationValidationParametersDTO;
    }

    /**
     * Builds the EAA validation parameters from the DTO
     *
     * @return {@link AttestationValidationParameters}
     */
    public AttestationValidationParameters build() {
        if (attestationValidationParametersDTO != null && attestationValidationParametersDTO.getSessionTranscript() != null) {
            return new RemoteMdocValidationParametersBuilder()
                    .setSessionTranscript(attestationValidationParametersDTO.getSessionTranscript())
                    .build();
        }
        return null;
    }

}
