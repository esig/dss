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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PDFTimestampingTest extends PKIFactoryAccess {
	
	@Test
	void test() {

		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		PAdESSignatureParameters extendParams = new PAdESSignatureParameters();
		
		extendParams.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
		extendParams.setSigningCertificate(getSigningCert());

		Exception exception = assertThrows(IllegalInputException.class, () -> service.extendDocument(doc, extendParams));
		assertEquals("No signatures found to be extended!", exception.getMessage());

		DSSDocument extendedDoc = service.timestamp(doc, new PAdESTimestampParameters());
		
		PDFDocumentValidator validator = new PDFDocumentValidator(extendedDoc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		
		assertEquals(0, simpleReport.getSignaturesCount());
		assertEquals(0, simpleReport.getSignatureIdList().size());
		assertNotNull(simpleReport.getDocumentFilename());
		
		assertEquals(1, simpleReport.getTimestampIdList().size());
		assertEquals(Indication.PASSED, simpleReport.getIndication(simpleReport.getFirstTimestampId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(simpleReport.getFirstTimestampId()));
		assertNull(detailedReport.getFirstSignatureId());
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getTimestampList().size());
		
		TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
		assertEquals(TimestampType.DOCUMENT_TIMESTAMP, timestampWrapper.getType());
		
		CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
		assertNotNull(signingCertificate);
		
		List<CertificateSourceType> sources = signingCertificate.getSources();
		assertTrue(Utils.isCollectionNotEmpty(sources));
		boolean timestampSource = false;
		for (CertificateSourceType source : sources) {
			if (CertificateSourceType.TIMESTAMP.equals(source)) {
				timestampSource = true;
				break;
			}
		}
		assertTrue(timestampSource);
		
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
