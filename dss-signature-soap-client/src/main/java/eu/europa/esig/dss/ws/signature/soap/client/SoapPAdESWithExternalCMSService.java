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

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalMessageDigestDTO;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalSignDocumentDTO;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

/**
 * This SOAP interface provides a possibility of PAdES signature creation using an external CMS signature provider
 *
 */
@WebService(targetNamespace = "http://signature.dss.esig.europa.eu/")
public interface SoapPAdESWithExternalCMSService extends Serializable {

    /**
     * Creates a signature revision for the provided PDF document according
     * to the defined parameters and returns the message-digest computed on the extracted ByteRange content.
     *
     * @param pdfMessageDigest
     *            {@link PDFExternalMessageDigestDTO} containing a PDF document to be singed and signature parameters
     * @return {@link DigestDTO} representing message-digest computed on the prepared PDF signature byte range
     */
    @WebResult(name = "response")
    DigestDTO getMessageDigest(@WebParam(name = "pdfMessageDigest") PDFExternalMessageDigestDTO pdfMessageDigest);

    /**
     * Signs the {@code toSignDocument} by incorporating the provided {@code cmsSignature}
     * within computed PDF signature revision.
     *
     * @param pdfSignDocument
     *            {@link PDFExternalSignDocumentDTO} containing a PDF document, set of driven signature creation
     *            parameters and a CMS signature document
     * @return {@link RemoteDocument} representing a PDF signed document embedding the provided CMS signature
     */
    @WebResult(name = "response")
    RemoteDocument signDocument(@WebParam(name = "pdfSignDocument") PDFExternalSignDocumentDTO pdfSignDocument);

}
