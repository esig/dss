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
package eu.europa.esig.dss.cookbook.example.snippets.ws.soap;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.ws.validation.soap.SoapDocumentValidationServiceImpl;
import eu.europa.esig.dss.ws.validation.soap.client.SoapDocumentValidationService;

import java.io.File;

public class SoapValidationServiceSnippet {

    @SuppressWarnings("unused")
    public void demo() throws Exception {

        // tag::demo[]
        // import eu.europa.esig.dss.ws.validation.soap.SoapDocumentValidationServiceImpl;
        // import eu.europa.esig.dss.ws.validation.soap.client.SoapDocumentValidationService;

        // Initialize the soap client
        SoapDocumentValidationService validationService = new SoapDocumentValidationServiceImpl();

        // end::demo[]

        // Initialize document to be validated
        FileDocument signatureToValidate = new FileDocument(new File("src/test/resources/XAdESLTA.xml"));
        RemoteDocument signedFile = RemoteDocumentConverter.toRemoteDocument(signatureToValidate);

        // Create the object containing data to be validated
        DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, (RemoteDocument) null, null);

        // Validate the signature
        WSReportsDTO result = validationService.validateSignature(toValidate);
    }

}
