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
package eu.europa.esig.dss.signature;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import org.apache.cxf.annotations.WSDLDocumentation;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.ToBeSigned;

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
@WebService
@WSDLDocumentation("The signing web service allows to create a new signature or to extend existing one. Different forms of signature:XAdES, ASiC-S and ASiC-E are accepted.\n"
		+ " The digital signature of a document in a web environment is performed in three steps:\n"
		+ " 1. Creating a byte stream representing the data to be signed.\n"
		+ " 2. Hashing of the data previously obtained and its encryption. This step is performed locally (not by the web service).\n"
		+ " 3. The creation of the envelope containing all the elements of a digital signature.\n" + " The process is controlled by a set of parameters.")
public interface SoapMultipleDocumentsSignatureService extends Serializable {

	/**
	 * This method computes the digest to be signed
	 *
	 * @param dataToSign
	 *            a DTO which contains the documents to sign and parameters
	 * @return the data to be signed
	 * @throws DSSException
	 */
	@WSDLDocumentation("This method retrieves the stream of data that need to be hashed and encrypted. It takes one parameter composed of : the documents to sign and the set of parameters.")
	@WebResult(name = "response")
	ToBeSigned getDataToSign(@WebParam(name = "dataToSignDTO") DataToSignMultipleDocumentsDTO dataToSign) throws DSSException;

	/**
	 * This web service operation signs a document according to a previously signed digest, a level of signature, some
	 * signature properties and keyInfo.
	 *
	 * @param signDocument
	 *            a DTO which contains the documents to be signed, the parameters and the signature value
	 * @return the signed document
	 * @throws DSSException
	 */
	@WSDLDocumentation("This method creates the signature containing the provided encrypted hash value and all requested elements. It requests one paramaters composed of : the documents to "
			+ "sign, the set of driving parameters and the encrypted hash value of bytes that need to be protected by the digital signature.")
	@WebResult(name = "response")
	RemoteDocument signDocument(@WebParam(name = "signDocumentDTO") SignMultipleDocumentDTO signDocument) throws DSSException;

	/**
	 * This web service operation extends the signature of a given document to the level of the signature provided. The
	 * document is only changed, if the given signature level is 'higher' than the signature level of the document.
	 *
	 * @param extendDocument
	 *            a DTO which contains the document to be extented and the parameters
	 * @return the document with an extended signature
	 * @throws DSSException
	 */
	@WSDLDocumentation("This method Extends the level of the signature(s) linked to the given document. It takes one parameter composed of : the document with the signature(s), "
			+ "the set of driving parameters.")
	@WebResult(name = "response")
	RemoteDocument extendDocument(@WebParam(name = "extendDocumentDTO") ExtendDocumentDTO extendDocument) throws DSSException;

}
