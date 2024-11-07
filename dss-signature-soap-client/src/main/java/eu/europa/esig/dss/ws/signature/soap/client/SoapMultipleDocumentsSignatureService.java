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
package eu.europa.esig.dss.ws.signature.soap.client;

import java.io.Serializable;

import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignMultipleDocumentsDTO;
import eu.europa.esig.dss.ws.signature.dto.ExtendDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignMultipleDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.TimestampMultipleDocumentDTO;

/**
 * Interface for the Contract of the Signature Web Service. The signing web service allows to create a new signature or
 * to extend existing one. Different forms of signature:
 * XAdES, ASiC-S or ASiC-E are accepted.
 * The digital signature of a document in a web environment is performed in three steps:
 * 1. Creating a byte stream representing the data to be signed.
 * 2. Hashing of the data previously obtained and its encryption.
 * 3. The creation of the envelope containing all the elements of a digital signature.
 * The process is controlled by a set of parameters.
 */
@WebService(targetNamespace = "http://signature.dss.esig.europa.eu/")
public interface SoapMultipleDocumentsSignatureService extends Serializable {

	/**
	 * This method computes the digest to be signed
	 *
	 * @param dataToSign
	 *            a DTO which contains the documents to sign and parameters
	 * @return the data to be signed
	 */
	@WebResult(name = "response")
	ToBeSignedDTO getDataToSign(@WebParam(name = "dataToSignDTO") DataToSignMultipleDocumentsDTO dataToSign);

	/**
	 * This web service operation signs a document according to a previously signed digest, a level of signature, some
	 * signature properties and keyInfo.
	 *
	 * @param signDocument
	 *            a DTO which contains the documents to be signed, the parameters and the signature value
	 * @return the signed document
	 */
	@WebResult(name = "response")
	RemoteDocument signDocument(@WebParam(name = "signDocumentDTO") SignMultipleDocumentDTO signDocument);

	/**
	 * This web service operation extends the signature of a given document to the level of the signature provided. The
	 * document is only changed, if the given signature level is 'higher' than the signature level of the document.
	 *
	 * @param extendDocument
	 *            a DTO which contains the document to be extented and the parameters
	 * @return the document with an extended signature
	 */
	@WebResult(name = "response")
	RemoteDocument extendDocument(@WebParam(name = "extendDocumentDTO") ExtendDocumentDTO extendDocument);

	/**
	 * This web service operation timestamps a given document corresponding to the provided timestamp parameters.
	 *
	 * @param timestampDocumentDTO
	 *            a DTO which contains the documents to be timestamped and the parameters
	 * @return the document with a timestamp
	 */
	@WebResult(name = "response")
	RemoteDocument timestampDocument(@WebParam(name = "timestampDocumentDTO") TimestampMultipleDocumentDTO timestampDocumentDTO);

}
