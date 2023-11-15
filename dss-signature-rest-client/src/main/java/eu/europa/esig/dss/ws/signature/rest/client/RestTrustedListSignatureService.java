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

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.dto.SignTrustedListDTO;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.io.Serializable;

/**
 * This REST interface provides operations for the XML Trusted List signing.
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestTrustedListSignatureService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed based on the given XML Trusted List and parameters.
     *
     * @param dataToSign {@link DataToSignTrustedListDTO} a DTO with the needed information
     *                                                   (trusted list and parameters) to compute the data to be signed
     * @return {@link ToBeSignedDTO} the data to be signed
     */
    @POST
    @Path("getDataToSign")
    ToBeSignedDTO getDataToSign(DataToSignTrustedListDTO dataToSign);

    /**
     * Signs the XML Trusted List with the provided signatureValue.
     *
     * NOTE: the same set of parameters shall be used for this method call,
     *       as it was for {@code getDataToSign(dataToSign)} method
     *
     * @param signTrustedList {@link SignTrustedListDTO} a DTO with the needed information
     *                                               (trusted list, parameter and signature value) to generate
     *                                               the signed XML Trusted List with an enveloped signature
     * @return {@link RemoteDocument} the signed document
     */
    @POST
    @Path("signDocument")
    RemoteDocument signDocument(SignTrustedListDTO signTrustedList);

}
