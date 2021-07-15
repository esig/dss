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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RetrieveOriginalDocumentTest {

	@TempDir
	static Path targetFolder;

	@Test
	public void getOriginalDocument() throws IOException {

		Path path = targetFolder.resolve("original.xml");
		String targetPath = path.toString();

		// tag::demo[]
		// We have our signed document, we want to retrieve the original/signed data
		DSSDocument signedDocument = new FileDocument("src/test/resources/signature-pool/signedXmlXadesB.xml");

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

		// Save the extracted original document if needed
		original.save(targetPath);
		// end::demo[]
		
		assertNotNull(original);
		assertTrue(path.toFile().exists());
		assertTrue(path.toFile().delete(), "Cannot delete the file");
		assertFalse(path.toFile().exists());

	}

}
