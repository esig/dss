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
package eu.europa.esig.dss.ws.signature.soap.client;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.CounterSignSignatureDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToBeCounterSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.ExtendDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.TimestampOneDocumentDTO;

/**
 * Interface for the Contract of the Signature Web Service. The signing web service allows to create a new signature or
 * to extend existing one. Different forms of signature:
 * XAdES, CAdES, PAdES, JAdES (as well as ASiC containers) are accepted.
 * <p>
 * The digital signature of a document in a web environment is performed in three steps:
 * 1. Creating a byte stream representing the data to be signed.
 * 2. Hashing of the data previously obtained and its encryption.
 * 3. The creation of the envelope containing all the elements of a digital signature.
 * <p>
 * The process is controlled by a set of parameters.
 */
@WebService(targetNamespace = "http://signature.dss.esig.europa.eu/")
public interface SoapDocumentSignatureService extends Serializable {

	/**
	 * This method computes the digest to be signed
	 *
	 * @param dataToSign {@link DataToSignOneDocumentDTO }a DTO which contains the
	 *                   document to sign and parameters
	 * @return {@link ToBeSignedDTO} the data to be signed
	 */
	@WebResult(name = "response")
	ToBeSignedDTO getDataToSign(@WebParam(name = "dataToSignDTO") DataToSignOneDocumentDTO dataToSign);

	/**
	 * This web service operation signs a document according to a previously signed
	 * digest, a level of signature, some signature properties and keyInfo.
	 *
	 * @param signDocument {@link SignOneDocumentDTO} a DTO which contains the
	 *                     document to be signed, the parameters and the signature
	 *                     value
	 * @return {@link RemoteDocument} the signed document
	 */
	@WebResult(name = "response")
	RemoteDocument signDocument(@WebParam(name = "signDocumentDTO") SignOneDocumentDTO signDocument);

	/**
	 * This web service operation extends the signature of a given document to the
	 * level of the signature provided. The document is only changed, if the given
	 * signature level is 'higher' than the signature level of the document.
	 *
	 * @param extendDocument {@link ExtendDocumentDTO} a DTO which contains the
	 *                       document to be extented and the parameters
	 * @return {@link RemoteDocument} the document with an extended signature
	 */
	@WebResult(name = "response")
	RemoteDocument extendDocument(@WebParam(name = "extendDocumentDTO") ExtendDocumentDTO extendDocument);

	/**
	 * This web service operation timestamps a document according to the provided
	 * timestamp parameters.
	 *
	 * @param timestampDocument {@link TimestampOneDocumentDTO} a DTO which contains
	 *                          the document to be timestamped and timestamp
	 *                          parameters
	 * @return {@link RemoteDocument} a timestamped document
	 */
	@WebResult(name = "response")
	RemoteDocument timestampDocument(@WebParam(name = "timestampDocumentDTO") TimestampOneDocumentDTO timestampDocument);

	/**
	 * Retrieves the data to be signed for counter signature creation
	 * 
	 * @param dataToBeCounterSigned {@link DataToBeCounterSignedDTO} a DTO with the
	 *                          required information (signatureDocument, parameters)
	 *                          to get data to be counter signed
	 * @return {@link DataToBeCounterSignedDTO} the data to be counter signed
	 */
	@WebResult(name = "response")
	ToBeSignedDTO getDataToBeCounterSigned(@WebParam(name = "dataToBeCounterSigned") DataToBeCounterSignedDTO dataToBeCounterSigned);

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
	@WebResult(name = "response")
	RemoteDocument counterSignSignature(@WebParam(name = "counterSignSignature") CounterSignSignatureDTO counterSignSignature);

}
