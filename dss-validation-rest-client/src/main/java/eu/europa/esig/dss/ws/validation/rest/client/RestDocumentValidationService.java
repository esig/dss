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
package eu.europa.esig.dss.ws.validation.rest.client;

import java.io.Serializable;
import java.util.List;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;

/**
 * This REST interface provides operations for the validation of signature.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestDocumentValidationService extends Serializable {

	/**
	 * This method returns the result of the validation of the signed file. The
	 * results contains a Diagnostic Data, simple report, detailed report and
	 * ETSI Validation report
	 * 
	 * @param dataToValidate
	 *                       a {@code DataToValidateDTO} which contains the
	 *                       signature, the optional original document(s) and the
	 *                       optional validation policy
	 * @return a {@code ReportsDTO} with  4 reports : the diagnostic data, the
	 *         detailed report, the simple report and the ETSI validation report
	 */
	@POST
	@Path("validateSignature")
	WSReportsDTO validateSignature(DataToValidateDTO dataToValidate);

	/**
	 * This method returns the original document(s) for the given signed file and
	 * optionally the signatureId.
	 * 
	 * @param dataToValidate
	 *                       a {@code DataToValidateDTO} which contains the
	 *                       signature, the optional original document and the
	 *                       optional signatureId
	 * @return a List of {@code RemoteDocument}
	 */
	@POST
	@Path("getOriginalDocuments")
	List<RemoteDocument> getOriginalDocuments(DataToValidateDTO dataToValidate);

}
