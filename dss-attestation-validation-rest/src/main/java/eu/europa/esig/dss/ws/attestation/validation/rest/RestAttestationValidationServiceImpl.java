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
package eu.europa.esig.dss.ws.attestation.validation.rest;

import eu.europa.esig.dss.ws.attestation.validation.common.RemoteAttestationValidationService;
import eu.europa.esig.dss.ws.attestation.validation.dto.AttestationToValidateDTO;
import eu.europa.esig.dss.ws.attestation.validation.rest.client.RestAttestationValidationService;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;

/**
 * REST implementation of the attestation validation service
 *
 */
public class RestAttestationValidationServiceImpl implements RestAttestationValidationService {

    private static final long serialVersionUID = -7198332175850813486L;

    /** The validation service to use */
    private RemoteAttestationValidationService validationService;

    /**
     * Default construction instantiating object with null RemoteDocumentValidationService
     */
    public RestAttestationValidationServiceImpl() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param validationService {@link RemoteAttestationValidationService}
     */
    public void setValidationService(RemoteAttestationValidationService validationService) {
        this.validationService = validationService;
    }

    @Override
    public WSReportsDTO validateEAA(AttestationToValidateDTO dataToValidate) {
        return validationService.validateEAA(dataToValidate);
    }

}
