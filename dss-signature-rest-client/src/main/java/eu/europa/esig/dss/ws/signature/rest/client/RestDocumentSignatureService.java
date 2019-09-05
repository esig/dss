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
package eu.europa.esig.dss.ws.signature.rest.client;

import java.io.Serializable;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.ExtendDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignOneDocumentDTO;

/**
 * This REST interface provides operations for the signature creation and for its extension.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestDocumentSignatureService extends Serializable {

	/**
	 * Retrieves the bytes of the data that need to be signed based on the toSignDocument and parameters.
	 * 
	 * @param dataToSign
	 *            a DTO with the needed information (document and parameters) to compute the data to be signed
	 * @return the data to be signed
	 */
	@POST
	@Path("getDataToSign")
	ToBeSignedDTO getDataToSign(DataToSignOneDocumentDTO dataToSign);

	/**
	 * Signs the toSignDocument with the provided signatureValue.
	 * 
	 * @param signDocument
	 *            a DTO with the needed information (document, parameter and signature value) to generate the signed
	 *            document
	 * @return the signed document
	 */
	@POST
	@Path("signDocument")
	RemoteDocument signDocument(SignOneDocumentDTO signDocument);

	/**
	 * Extends the level of the signatures in the toExtendDocument
	 * 
	 * @param extendDocument
	 *            a DTO with the needed information (the signed document and extension parameters) to generate the
	 *            extended document
	 * @return the extended document
	 */
	@POST
	@Path("extendDocument")
	RemoteDocument extendDocument(ExtendDocumentDTO extendDocument);

}
