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
import eu.europa.esig.dss.ws.signature.dto.DataToSignExternalCmsDTO;
import eu.europa.esig.dss.ws.signature.dto.SignMessageDigestExternalCmsDTO;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.Serializable;

/**
 * This REST interface provides a possibility of CMS signature creation suitable for PAdES signing
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestExternalCMSService extends Serializable {

    /**
     * Returns a DTBS (Data To Be Signed) for Signature Value creation.
     *
     * @param dataToSign
     *            {@link DataToSignExternalCmsDTO} containing message-digest computed on PDF's signature ByteRange
     *            and a set of signature driving parameters
     * @return {@link ToBeSignedDTO} data to be signed representation
     */
    @POST
    @Path("getDataToSign")
    ToBeSignedDTO getDataToSign(DataToSignExternalCmsDTO dataToSign);

    /**
     * Creates a CMS signature signing the provided {@code messageDigest} compliant for PAdES signature enveloping.
     *
     * @param signMessageDigest
     *            {@link SignMessageDigestExternalCmsDTO} containing message-digest computed on PDF's signature ByteRange,
     *            set of signature driving parameters and a signatureValue computed on DTBS
     * @return {@link RemoteDocument} representing a CMS signature suitable for PAdES-BASELINE creation
     */
    @POST
    @Path("signMessageDigest")
    RemoteDocument signMessageDigest(SignMessageDigestExternalCmsDTO signMessageDigest);

}
