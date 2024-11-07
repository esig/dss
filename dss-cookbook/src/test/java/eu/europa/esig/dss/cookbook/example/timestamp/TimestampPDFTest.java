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
package eu.europa.esig.dss.cookbook.example.timestamp;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class TimestampPDFTest extends CookbookTools {
	
	@Test
	void test() throws Exception {

		// tag::creation[]
		// import eu.europa.esig.dss.model.DSSDocument;
		// import eu.europa.esig.dss.model.FileDocument;
		// import java.io.File;
		// import eu.europa.esig.dss.pades.signature.PAdESService;

		// Loads a document to be timestamped
		DSSDocument documentToTimestamp = new FileDocument(new File("src/main/resources/hello-world.pdf"));
		
		// Configure a PAdES service for PDF timestamping
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		// Execute the timestamp method
		DSSDocument timestampedDoc = service.timestamp(documentToTimestamp, new PAdESTimestampParameters());
		// end::creation[]

		// tag::validation[]
		// import eu.europa.esig.dss.validation.SignedDocumentValidator;
		// import eu.europa.esig.dss.validation.reports.Reports;

		// Load a document validator. The appropriate validator class will be determined automatically.
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(timestampedDoc);
		// Configure the validator. Provide a certificate verifier.
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		// Validate the document
		Reports reports = validator.validateDocument();
		// end::validation[]
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(0, diagnosticData.getSignatures().size());
		assertEquals(1, diagnosticData.getTimestampList().size());
		
	}

}
