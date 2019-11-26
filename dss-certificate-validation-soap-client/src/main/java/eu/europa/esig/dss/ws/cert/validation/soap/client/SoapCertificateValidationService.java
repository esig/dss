/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.cert.validation.soap.client;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;

/**
 * The validation web service allow to validate the provided certificate. Missing certificate from certificate chain
 * and a custom validation time can be provided.
 */
@WebService(targetNamespace = "http://certificate-validation.dss.esig.europa.eu/")
public interface SoapCertificateValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the certificate. The
	 * results contains a Diagnostic Data, simple certificate report and detailed report
	 * 
	 * @param certificateToValidate
	 *                       a {@code CertificateToValidateDTO} which contains the
	 *                       certificate, the certificate chain and validation time
	 * @return a {@code WSCertificateReportsDTO} with the 3 reports : the diagnostic data, the
	 *         detailed report and the simple certificate report
	 */
	@WebResult(name = "WSReportsDTO")
	WSCertificateReportsDTO validateCertificate(@WebParam(name = "dataToValidateDTO") CertificateToValidateDTO certificateToValidate);

}
