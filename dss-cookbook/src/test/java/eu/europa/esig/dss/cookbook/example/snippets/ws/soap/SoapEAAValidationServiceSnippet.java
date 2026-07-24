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
package eu.europa.esig.dss.cookbook.example.snippets.ws.soap;

// tag::demo[]
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.eaa.validation.dto.AttestationToValidateDTO;
import eu.europa.esig.dss.ws.eaa.validation.dto.AttestationValidationParametersDTO;
import eu.europa.esig.dss.ws.eaa.validation.soap.SoapAttestationValidationServiceImpl;
import eu.europa.esig.dss.ws.eaa.validation.soap.client.SoapAttestationValidationService;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;

public class SoapEAAValidationServiceSnippet extends CookbookTools {

    @SuppressWarnings("unused")
    public void demo() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // Instantiate the REST client
            SoapAttestationValidationService soapClient = new SoapAttestationValidationServiceImpl();

            // Initialize EAA document to be validated
            FileDocument signatureToValidate = new FileDocument("src/test/resources/mdoc-eaa.cbor");
            RemoteDocument signedDocument = RemoteDocumentConverter.toRemoteDocument(signatureToValidate);

            // Initialize validation parameters, when needed
            AttestationValidationParametersDTO validationParameters = new AttestationValidationParametersDTO();

            // E.g. provide SessionTranscript, required for mdoc's key binding signature validation
            FileDocument sessionTranscript = new FileDocument("src/test/resources/sessionTranscript.cbor");
            validationParameters.setSessionTranscript(RemoteDocumentConverter.toRemoteDocument(sessionTranscript));

            // Initialize XML validation policy to be used (optional, if not provided the default policy will be used)
            FileDocument policyFile = new FileDocument("src/test/resources/policy.xml");
            RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(policyFile);
            
            // Create the object containing data to be validated
            AttestationToValidateDTO toValidate = new AttestationToValidateDTO(signedDocument, validationParameters, policy);

            // Validate the Attestation Presentation
            WSReportsDTO result = soapClient.validateEAA(toValidate);
        }

    }

}
// end::demo[]