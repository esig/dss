package eu.europa.esig.dss.cookbook.example.validate;

import java.io.IOException;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class RetrieveOriginalDocumentTest {

	@Test
	public void getOriginalDocument() throws IOException {

		// tag::demo[]

		// We have our signed document, we want to retrieve the original/signed data
		DSSDocument signedDocument = new FileDocument("src/test/resources/signedXmlXadesB.xml");

		// We create an instance of DocumentValidator. DSS automatically selects the validator depending of the
		// signature file
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

		// We set a certificate verifier. It handles the certificate pool, allows to check the certificate status,...
		documentValidator.setCertificateVerifier(new CommonCertificateVerifier());

		// We retrieve the found signatures
		List<AdvancedSignature> signatures = documentValidator.getSignatures();

		// We select the wanted signature (the first one in our current case)
		AdvancedSignature advancedSignature = signatures.get(0);

		// We call get original document with the related signature id (DSS unique ID)
		List<DSSDocument> originalDocuments = documentValidator.getOriginalDocuments(advancedSignature.getId());

		// We can have one or more original documents depending of the signature (ASiC, PDF,...)
		DSSDocument original = originalDocuments.get(0);

		original.save("target/original.xml");
		// end::demo[]

	}

}
