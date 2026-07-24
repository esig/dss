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
package eu.europa.esig.dss.ws.eaa.validation.soap.client;

import eu.europa.esig.dss.ws.eaa.validation.dto.AttestationToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

import java.io.Serializable;

/**
 * This SOAP interface provides operations for the validation of attestation presentation.
 *
 */
@WebService(targetNamespace = "http://eaa.validation.dss.esig.europa.eu/")
public interface SoapAttestationValidationService extends Serializable {

    /**
     * This method returns the result of the validation of the Attestation Presentation.
     * The results contain a Diagnostic Data, simple report, detailed report and
     * ETSI Validation report
     *
     * @param dataToValidate
     *                       a {@code EAAToValidateDTO} which contains the
     *                       EAA, the optional validation parameters
     * @return a {@code ReportsDTO} with  4 reports : the diagnostic data, the
     *         detailed report, the simple report and the ETSI validation report
     */
    @WebResult(name = "WSReportsDTO")
    WSReportsDTO validateEAA(@WebParam(name = "dataToValidateDTO") AttestationToValidateDTO dataToValidate);

}
