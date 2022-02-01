package eu.europa.esig.dss.cookbook.example.snippets.ws.rest;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import eu.europa.esig.dss.ws.validation.rest.RestDocumentValidationServiceImpl;
import eu.europa.esig.dss.ws.validation.rest.client.RestDocumentValidationService;

import java.io.File;

public class RestValidationServiceSnippet {

    @SuppressWarnings("unused")
    public void demo() throws Exception {

        // tag::demo[]

        // Initialize the rest client
        RestDocumentValidationService validationService = new RestDocumentValidationServiceImpl();

        // Initialize document to be validated
        FileDocument signatureToValidate = new FileDocument(new File("src/test/resources/XAdESLTA.xml"));
        RemoteDocument signedDocument = RemoteDocumentConverter.toRemoteDocument(signatureToValidate);

        // Initialize original document file to be provided as detached content (optional)
        FileDocument detachedFile = new FileDocument("src/test/resources/sample.xml");
        RemoteDocument originalDocument = RemoteDocumentConverter.toRemoteDocument(detachedFile);

        // Initialize XML validation policy to be used (optional, if not provided the default policy will be used)
        FileDocument policyFile = new FileDocument("src/test/resources/policy.xml");
        RemoteDocument policy = RemoteDocumentConverter.toRemoteDocument(policyFile);

        // Create the object containing data to be validated
        DataToValidateDTO toValidate = new DataToValidateDTO(signedDocument, originalDocument, policy);

        // Validate the signature
        WSReportsDTO result = validationService.validateSignature(toValidate);

        // end::demo[]
    }

}
