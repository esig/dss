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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

public class SignedDocumentValidatorTest {

	@Test
	public void testXmlUTF8() {
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/sample.xml")));
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlUTF8InMemory() throws IOException {
		FileInputStream fis = new FileInputStream(new File("src/test/resources/sample.xml"));
		byte[] byteArray = Utils.toByteArray(fis);
		Utils.closeQuietly(fis);
		DSSDocument document = new InMemoryDocument(byteArray);
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlISO() {
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/sampleISO.xml")));
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlUISOInMemory() throws IOException {
		FileInputStream fis = new FileInputStream(new File("src/test/resources/sampleISO.xml"));
		byte[] byteArray = Utils.toByteArray(fis);
		Utils.closeQuietly(fis);
		DSSDocument document = new InMemoryDocument(byteArray);
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}
	
	@Test
	public void internationalizationTest() {
		Locale systemLocale = Locale.getDefault();
		try {
			Locale.setDefault(Locale.ENGLISH);
			DSSDocument document = new FileDocument("src/test/resources/validation/dss-signed.xml");
			testMessages(document, Locale.getDefault(), null);
			testMessages(document, Locale.ENGLISH, "The certificate path is not trusted!");
			testMessages(document, Locale.FRENCH, "Le chemin du certificat n'est pas de confiance !");
			testMessages(document, Locale.GERMAN, "The certificate path is not trusted!");
		} finally {
			Locale.setDefault(systemLocale); // restore default
		}
	}
	
	private void testMessages(DSSDocument document, Locale locale, String expectedErrorMessage) {
		DefaultSignatureProcessExecutor processExecutor = new DefaultSignatureProcessExecutor();
		processExecutor.setLocale(locale);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setProcessExecutor(processExecutor);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		
		ResourceBundle bundle = ResourceBundle.getBundle("dss-messages", locale);
		Set<String> messageValues = getValues(bundle);
		
		Set<String> errors = detailedReport.getErrors(detailedReport.getFirstSignatureId());
		for (String error : errors) {
			assertTrue(messageValues.contains(error));
		}
		if (expectedErrorMessage != null) {
			assertTrue(errors.contains(expectedErrorMessage));
		}
	}
	
	private Set<String> getValues(ResourceBundle bundle) {
		Set<String> values = new HashSet<String>();
		for (String key : bundle.keySet()) {
			values.add(bundle.getString(key));
		}
		return values;
	}
	
}
