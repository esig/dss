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
package eu.europa.esig.dss.ws;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import org.apache.cxf.annotations.WSDLDocumentation;

import eu.europa.esig.dss.DSSException;

/**
 * Interface for the Contract of the Signature Web Service. The signing web service allows to create a new signature or to extend existing one. Different forms of signature:
 * XAdES, CAdES, PAdES, ASiC-S are accepted.
 * The digital signature of a document in a web environment is performed in three steps:
 * 1. Creating a byte stream representing the data to be signed.
 * 2. Hashing of the data previously obtained and its encryption.
 * 3. The creation of the envelope containing all the elements of a digital signature.
 * The process is controlled by a set of parameters.
 *
 *
 */
@WebService
@WSDLDocumentation("The signing web service allows to create a new signature or to extend existing one. Different forms of signature:XAdES, CAdES, PAdES, ASiC-S are accepted.\n" +
      " The digital signature of a document in a web environment is performed in three steps:\n" +
      " 1. Creating a byte stream representing the data to be signed.\n" +
      " 2. Hashing of the data previously obtained and its encryption. This step is performed locally (not by the web service).\n" +
      " 3. The creation of the envelope containing all the elements of a digital signature.\n" +
      " The process is controlled by a set of parameters.")
public interface SignatureService {

    /**
     * @param document     the document that shall be signed
     * @param wsParameters the container for the matching SignedProperties
     * @return
     * @throws DSSException
     */
    @WSDLDocumentation("This method retrieves the stream of data that need to be hashed and encrypted. It takes two parameters: the document to sign and the set of parameters.")
    @WebResult(name = "response")
    public byte[] getDataToSign(@WebParam(name = "document") final WSDocument document, @WebParam(name = "wsParameters")
    final WSParameters wsParameters) throws DSSException;

    /**
     * This web service operation signs a document according to a previously signed digest, a level of signature, some
     * signature properties and keyInfo.
     *
     * @param document     the document that shall be signed
     * @param wsParameters the container for the matching SignedProperties
     * @return the signed document
     * @throws DSSException
     */
    @WSDLDocumentation("This method creates the signature containing the provided encrypted hash value and all requested elements. It requests three parameters: the document to " +
          "sign, the set of driving parameters and the encrypted hash value of bytes that need to be protected by the digital signature.")
    @WebResult(name = "response")
    WSDocument signDocument(@WebParam(name = "document") final WSDocument document, @WebParam(name = "wsParameters") final WSParameters wsParameters,
                            @WebParam(name = "signatureValue") final byte[] signatureValue) throws DSSException;

    /**
     * This web service operation extends the signature of a given document to the level of the signature provided. The
     * document is only changed, if the given signature level is 'higher' than the signature level of the document.
     *
     * @param signedDocument the signed document
     * @param wsParameters   the container for the matching SignedProperties
     * @return the document with an extended signature
     * @throws DSSException
     */
    @WSDLDocumentation("This method Extends the level of the signature(s) linked to the given document. It takes two parameters: the document with the signature(s), " +
          "the set of driving parameters.")
    @WebResult(name = "response")
    WSDocument extendSignature(@WebParam(name = "signedDocument") final WSDocument signedDocument,
                               @WebParam(name = "wsParameters") final WSParameters wsParameters) throws DSSException;

}