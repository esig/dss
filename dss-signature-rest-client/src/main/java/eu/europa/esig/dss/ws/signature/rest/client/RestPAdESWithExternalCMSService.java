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

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalMessageDigestDTO;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalSignDocumentDTO;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.io.Serializable;

/**
 * This REST interface provides a possibility of PAdES signature creation using an external CMS signature provider
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestPAdESWithExternalCMSService extends Serializable {

    /**
     * Creates a signature revision for the provided PDF document according
     * to the defined parameters and returns the message-digest computed on the extracted ByteRange content.
     *
     * @param pdfMessageDigest
     *            {@link PDFExternalMessageDigestDTO} containing a PDF document to be singed and signature parameters
     * @return {@link DigestDTO} representing message-digest computed on the prepared PDF signature byte range
     */
    @POST
    @Path("getMessageDigest")
    DigestDTO getMessageDigest(PDFExternalMessageDigestDTO pdfMessageDigest);

    /**
     * Signs the {@code toSignDocument} by incorporating the provided {@code cmsSignature}
     * within computed PDF signature revision.
     *
     * @param pdfSignDocument
     *            {@link PDFExternalSignDocumentDTO} containing a PDF document, set of driven signature creation
     *            parameters and a CMS signature document
     * @return {@link RemoteDocument} representing a PDF signed document embedding the provided CMS signature
     */
    @POST
    @Path("signDocument")
    RemoteDocument signDocument(PDFExternalSignDocumentDTO pdfSignDocument);

}
