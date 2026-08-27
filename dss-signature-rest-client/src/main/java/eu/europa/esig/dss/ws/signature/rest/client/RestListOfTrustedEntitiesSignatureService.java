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
package eu.europa.esig.dss.ws.signature.rest.client;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignListOfTrustedEntitiesDTO;
import eu.europa.esig.dss.ws.signature.dto.SignListOfTrustedEntitiesDTO;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.io.Serializable;

/**
 * This REST interface provides operations for the List of Trusted Entities signing.
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestListOfTrustedEntitiesSignatureService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed based on the given List of Trusted Entities and parameters.
     *
     * @param dataToSign {@link DataToSignListOfTrustedEntitiesDTO} a DTO with the needed information
     *                   (list of trusted entities and parameters) to compute the data to be signed
     * @return {@link ToBeSignedDTO} the data to be signed
     */
    @POST
    @Path("getDataToSign")
    ToBeSignedDTO getDataToSign(DataToSignListOfTrustedEntitiesDTO dataToSign);

    /**
     * Signs the List of Trusted Entities with the provided signatureValue.
     * <p>
     * NOTE: the same set of parameters shall be used for this method call,
     *       as it was for {@code getDataToSign(dataToSign)} method
     *
     * @param signListOfTrustedEntities {@link SignListOfTrustedEntitiesDTO} a DTO with the needed information
     *                                  (list of trusted entities, parameter and signature value) to generate
     *                                  the signed List of Trusted Entities with an enveloped signature
     * @return {@link RemoteDocument} the signed document
     */
    @POST
    @Path("signDocument")
    RemoteDocument signDocument(SignListOfTrustedEntitiesDTO signListOfTrustedEntities);

}
