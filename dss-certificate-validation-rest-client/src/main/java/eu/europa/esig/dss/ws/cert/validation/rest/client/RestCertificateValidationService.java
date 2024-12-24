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
package eu.europa.esig.dss.ws.cert.validation.rest.client;
import java.io.Serializable;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;

/**
 * This REST interface provides operations for the validation of certificate.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestCertificateValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the signed file. The
	 * results contains a Diagnostic Data, simple certificate report and detailed report
	 * 
	 * @param certificateToValidate
	 *                       a {@code CertificateToValidateDTO} which contains the
	 *                       certificate, certificate chain and validation time
	 * @return a {@code CertificateReportsDTO} with the 3 reports : the diagnostic data, the
	 *         detailed report and the simple certificate report
	 */
	@POST
	@Path("validateCertificate")
	CertificateReportsDTO validateCertificate(CertificateToValidateDTO certificateToValidate);

}
