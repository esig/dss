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

import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.dto.SignTrustedListDTO;

import java.io.Serializable;

/**
 * SOAP interface provides services for XML Trusted List signing
 *
 */
@WebService(targetNamespace = "http://signature.dss.esig.europa.eu/")
public interface SoapTrustedListSignatureService extends Serializable {

    /**
     * This method computes the digest to be signed for XML Trusted List enveloped signature creation
     *
     * @param dataToSign {@link DataToSignOneDocumentDTO} a DTO which contains the XML Trusted List to be signed
     *                                                   and parameters
     * @return {@link ToBeSignedDTO} the data to be signed
     */
    @WebResult(name = "response")
    ToBeSignedDTO getDataToSign(@WebParam(name = "dataToSignDTO") DataToSignTrustedListDTO dataToSign);

    /**
     * This method created a signed XML Trusted List with an enveloped signature
     *
     * @param signTrustedList {@link SignTrustedListDTO} a DTO which contains the XMl Trusted List to be signed,
     *                                                  the parameters and the signature value
     * @return {@link RemoteDocument} the signed document
     */
    @WebResult(name = "response")
    RemoteDocument signDocument(@WebParam(name = "signDocumentDTO") SignTrustedListDTO signTrustedList);

}
