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
package eu.europa.esig.dss.ws.signature.rest;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.common.RemotePAdESWithExternalCMSService;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalMessageDigestDTO;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalSignDocumentDTO;
import eu.europa.esig.dss.ws.signature.rest.client.RestPAdESWithExternalCMSService;

/**
 * REST implementation of the remote PAdES signature with external CMS service
 *
 */
public class RestPAdESWithExternalCMSServiceImpl implements RestPAdESWithExternalCMSService {

    private static final long serialVersionUID = 7258729288847441656L;

    /** The service to use */
    private RemotePAdESWithExternalCMSService service;

    /**
     * Default construction instantiating object with null RestPAdESWithExternalCMSServiceImpl
     */
    public RestPAdESWithExternalCMSServiceImpl() {
        // empty
    }

    /**
     * Sets the remote PAdES signature with external CMS service
     *
     * @param service {@link RemotePAdESWithExternalCMSService}
     */
    public void setService(RemotePAdESWithExternalCMSService service) {
        this.service = service;
    }

    @Override
    public DigestDTO getMessageDigest(PDFExternalMessageDigestDTO pdfMessageDigest) {
        return service.getMessageDigest(pdfMessageDigest.getToSignDocument(), pdfMessageDigest.getParameters());
    }

    @Override
    public RemoteDocument signDocument(PDFExternalSignDocumentDTO pdfSignDocument) {
        return service.signDocument(pdfSignDocument.getToSignDocument(), pdfSignDocument.getParameters(),
                pdfSignDocument.getCmsDocument());
    }

}
