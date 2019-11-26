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
package eu.europa.esig.dss.pades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1444Test {

	@Test
	public void test() throws IOException {
		Exception exception = assertThrows(IOException.class, () -> {
			try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted.pdf")) {
				PDDocument.load(is);
			}
		});
		assertEquals("Page tree root must be a dictionary", exception.getMessage());
	}

	@Test
	public void testValidation() throws IOException {
		Exception exception = assertThrows(DSSException.class, () -> {
			try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted.pdf")) {
				PDFDocumentValidator val = new PDFDocumentValidator(new InMemoryDocument(is));
				val.getSignatures();
			}
		});
		assertEquals("Cannot analyze signatures : Page tree root must be a dictionary", exception.getMessage());
	}

	@Test
	public void test2() throws IOException {
		Exception exception = assertThrows(IOException.class, () -> {
			try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted2.pdf")) {
				PDDocument.load(is);
			}
		});
		assertEquals("Page tree root must be a dictionary", exception.getMessage());
	}

	@Test
	public void test2Validation() throws IOException {
		Exception exception = assertThrows(DSSException.class, () -> {
			try (InputStream is = getClass().getResourceAsStream("/EmptyPage-corrupted2.pdf")) {
				PDFDocumentValidator val = new PDFDocumentValidator(new InMemoryDocument(is));
				val.getSignatures();
			}
		});
		assertEquals("Cannot analyze signatures : Page tree root must be a dictionary", exception.getMessage());
	}

	@Test
	public void test3() throws IOException {
		Exception exception = assertThrows(IOException.class, () -> {
			try (InputStream is = getClass().getResourceAsStream("/small-red.jpg")) {
				PDDocument.load(is);
			}
		});
		assertEquals("Error: End-of-File, expected line", exception.getMessage());
	}

	@Test
	public void test3bis() throws IOException {
		Exception exception = assertThrows(DSSException.class, () -> {
			try (InputStream is = getClass().getResourceAsStream("/small-red.jpg")) {
				PDFDocumentValidator val = new PDFDocumentValidator(new InMemoryDocument(is));
				val.getSignatures();
			}
		});
		assertEquals("Cannot analyze signatures : Error: End-of-File, expected line", exception.getMessage());
	}

	@Test
	public void test4() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/sample.pdf")) {
			PDDocument document = PDDocument.load(is);
			assertNotNull(document);
		}
	}

	/**
	 * Positive test with default policy with PLAIN-ECDSA constrains. 
	 * @throws IOException
	 */
	@Test
	public void test5() throws IOException {
	  	DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-PLAIN-ECDSA/TeleSec_PKS_eIDAS_QES_CA_1-baseline-b.pdf"));
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
	 * 
	 * Negative test with policy without PLAIN-ECDSA constrains.
	 * @throws IOException
	 */
	@Test
	public void test6() throws IOException {
	  	DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-PLAIN-ECDSA/TeleSec_PKS_eIDAS_QES_CA_1-baseline-b.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument(getClass().getResourceAsStream("/validation/dss-PLAIN-ECDSA/policy_without_PLAIN-ECDSA.xml"));
		assertNotNull(reports);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);
		XmlBasicBuildingBlocks xmlBasicBuildingBlocks = detailedReport.getBasicBuildingBlockById(diagnosticData.getFirstSignatureId());
		assertNotNull( xmlBasicBuildingBlocks );
		XmlConclusion xmlConclusion = xmlBasicBuildingBlocks.getConclusion();
		assertNotNull( xmlConclusion );
		List<XmlName> xmlNames = xmlConclusion.getErrors();
		assertNotNull( xmlNames );
		for(int i = 0; i < xmlNames.size(); i++)
		{
		  if( "ASCCM_ANS_1".equals( xmlNames.get( i ).getNameId() ) )
		  {
		    assertEquals("The encryption algorithm is not authorised!", xmlNames.get(i).getValue());
		    return;
		  }
		}
		fail( "NOT FOUND!" );
	}
	
}
