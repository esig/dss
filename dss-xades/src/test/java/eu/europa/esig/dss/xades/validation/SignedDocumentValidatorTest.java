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

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignedDocumentValidatorTest {

	@Test
	public void testXmlUTF8() {
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/sample.xml")));
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlUTF8InMemory() throws IOException {
		FileInputStream fis = new FileInputStream("src/test/resources/sample.xml");
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
			testMessages(document, Locale.ENGLISH, "Unable to build a certificate chain up to a trusted list!");
			testMessages(document, Locale.FRENCH, "Impossible de remonter jusqu'à une liste de confiance !");
			testMessages(document, Locale.GERMAN, "Unable to build a certificate chain up to a trusted list!");
		} finally {
			Locale.setDefault(systemLocale); // restore default
		}
	}
	
	private void testMessages(DSSDocument document, Locale locale, String expectedErrorMessage) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setLocale(locale);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		
		ResourceBundle bundle = ResourceBundle.getBundle("dss-messages", locale);
		Set<String> messageValues = getValues(bundle);
		
		List<Message> errors = detailedReport.getQualificationErrors(detailedReport.getFirstSignatureId());
		for (Message error : errors) {
			assertTrue(messageValues.contains(error.getValue()));
		}
		List<String> messages = errors.stream().map(m -> m.getValue()).collect(Collectors.toList());
		if (expectedErrorMessage != null) {
			assertTrue(messages.contains(expectedErrorMessage));
		}
	}
	
	private Set<String> getValues(ResourceBundle bundle) {
		Set<String> values = new HashSet<>();
		for (String key : bundle.keySet()) {
			values.add(MessageFormat.format(bundle.getString(key), new Object[] {}));
		}
		return values;
	}
	
}
