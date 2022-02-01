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
