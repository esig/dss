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

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.CounterSignSignatureDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToBeCounterSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.ExtendDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.TimestampOneDocumentDTO;

/**
 * This REST interface provides operations for the signature creation and for its extension.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestDocumentSignatureService extends Serializable {

	/**
	 * Retrieves the bytes of the data that need to be signed based on the
	 * toSignDocument and parameters.
	 * 
	 * @param dataToSign {@link DataToSignOneDocumentDTO} a DTO with the needed
	 *                   information (document and parameters) to compute the data
	 *                   to be signed
	 * @return {@link ToBeSignedDTO} the data to be signed
	 */
	@POST
	@Path("getDataToSign")
	ToBeSignedDTO getDataToSign(DataToSignOneDocumentDTO dataToSign);

	/**
	 * Signs the toSignDocument with the provided signatureValue.
	 * 
	 * @param signDocument {@link SignOneDocumentDTO} a DTO with the needed
	 *                     information (document, parameter and signature value) to
	 *                     generate the signed document
	 * @return {@link RemoteDocument} the signed document
	 */
	@POST
	@Path("signDocument")
	RemoteDocument signDocument(SignOneDocumentDTO signDocument);

	/**
	 * Extends the level of the signatures in the toExtendDocument
	 * 
	 * @param extendDocument {@link ExtendDocumentDTO} a DTO with the needed
	 *                       information (the signed document and extension
	 *                       parameters) to generate the extended document
	 * @return {@link RemoteDocument} the extended document
	 */
	@POST
	@Path("extendDocument")
	RemoteDocument extendDocument(ExtendDocumentDTO extendDocument);
	
	/**
	 * Timestamps a toTimestampDocument with the provided parameters.
	 * 
	 * @param timestampDocument {@link TimestampOneDocumentDTO} a DTO with the
	 *                          needed information (document, timestamp parameters)
	 *                          to timestamp a document
	 * @return {@link RemoteDocument} a timestamped document
	 */
	@POST
	@Path("timestampDocument")
	RemoteDocument timestampDocument(TimestampOneDocumentDTO timestampDocument);

	/**
	 * Retrieves the data to be signed for counter signature creation
	 * 
	 * @param dataToBeCounterSigned {@link DataToBeCounterSignedDTO} a DTO with the
	 *                              required information (signatureDocument,
	 *                              parameters) to get data to be counter signed
	 * @return {@link DataToBeCounterSignedDTO} the data to be counter signed
	 */
	@POST
	@Path("getDataToBeCounterSigned")
	ToBeSignedDTO getDataToBeCounterSigned(DataToBeCounterSignedDTO dataToBeCounterSigned);

	/**
	 * Counter signs the defined signature
	 * 
	 * @param counterSignSignature {@link CounterSignSignatureDTO} a DTO with the
	 *                             required information (dataToBeCounterSigned,
	 *                             parameters, signatureValue) to counter sign a
	 *                             signature
	 * @return {@link RemoteDocument} representing a signatureDocument containing
	 *         the created counter signature
	 */
	@POST
	@Path("counterSignSignature")
	RemoteDocument counterSignSignature(CounterSignSignatureDTO counterSignSignature);

}
