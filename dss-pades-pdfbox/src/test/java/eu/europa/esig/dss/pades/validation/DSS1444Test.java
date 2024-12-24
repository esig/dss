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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class DSS1444Test {

	@Test
	void test() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted.pdf");
			 RandomAccessRead rar = new RandomAccessReadBuffer(is)) {
			Exception exception = assertThrows(IOException.class, () -> Loader.loadPDF(rar));
			assertEquals("Page tree root must be a dictionary", exception.getMessage());
		}
	}

	@Test
	void testValidation() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted.pdf")) {
			PDFDocumentAnalyzer analyzer = new PDFDocumentAnalyzer(new InMemoryDocument(is));
			Exception exception = assertThrows(DSSException.class, () -> analyzer.getSignatures());
			assertTrue(exception.getMessage().contains("Page tree root must be a dictionary"));
		}
	}

	@Test
	void test2() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted2.pdf");
			 RandomAccessRead rar = new RandomAccessReadBuffer(is)) {
			Exception exception = assertThrows(IOException.class, () -> Loader.loadPDF(rar));
			assertEquals("Page tree root must be a dictionary", exception.getMessage());
		}
	}

	@Test
	void test2Validation() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted2.pdf")) {
			PDFDocumentAnalyzer analyzer = new PDFDocumentAnalyzer(new InMemoryDocument(is));
			Exception exception = assertThrows(DSSException.class, () -> analyzer.getSignatures());
			assertTrue(exception.getMessage().contains("Page tree root must be a dictionary"));
		}
	}

	@Test
	void test3() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/small-red.jpg");
			 RandomAccessRead rar = new RandomAccessReadBuffer(is)) {
			Exception exception = assertThrows(IOException.class, () -> Loader.loadPDF(rar));
			assertTrue(exception.getMessage().contains("Error: End-of-File, expected line"));
		}
	}

	@Test
	void test4() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/sample.pdf");
			 RandomAccessRead rar = new RandomAccessReadBuffer(is);
			 PDDocument document = Loader.loadPDF(rar)) {
			assertNotNull(document);
		}
	}

	/**
	 * Positive test with default policy with PLAIN-ECDSA constrains.
	 */
	@Test
	void test5() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass()
				.getResourceAsStream("/validation/dss-PLAIN-ECDSA/TeleSec_PKS_eIDAS_QES_CA_1-baseline-b.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(EncryptionAlgorithm.PLAIN_ECDSA, signature.getEncryptionAlgorithm());
		assertTrue(signature.isBLevelTechnicallyValid());
		assertTrue(signature.isSignatureIntact());
		assertTrue(signature.isSignatureValid());
	}

	/**
	 * Negative test with policy without PLAIN-ECDSA constrains.
	 */
	@Test
	void test6() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass()
				.getResourceAsStream("/validation/dss-PLAIN-ECDSA/TeleSec_PKS_eIDAS_QES_CA_1-baseline-b.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument(
				getClass().getResourceAsStream("/validation/dss-PLAIN-ECDSA/policy_without_PLAIN-ECDSA.xml"));
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		XmlBasicBuildingBlocks xmlBasicBuildingBlocks = detailedReport
				.getBasicBuildingBlockById(diagnosticData.getFirstSignatureId());
		assertNotNull(xmlBasicBuildingBlocks);
		XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getConclusion();
		assertNotNull(xmlConclusion);
		List<XmlMessage> messages = xmlConclusion.getErrors();
		assertNotNull(messages);
		for (XmlMessage message : messages) {
			if (MessageTag.ASCCM_EAA_ANS.name().equals(message.getKey())) {
				assertEquals(new I18nProvider().getMessage(MessageTag.ASCCM_EAA_ANS, EncryptionAlgorithm.PLAIN_ECDSA.getName(), MessageTag.ACCM_POS_SIG_SIG),
						message.getValue());
				return;
			}
		}
		fail("NOT FOUND!");
	}

}
