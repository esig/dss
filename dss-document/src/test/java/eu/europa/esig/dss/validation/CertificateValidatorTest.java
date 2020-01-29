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
package eu.europa.esig.dss.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.util.GregorianCalendar;

import javax.xml.bind.JAXBException;
import javax.xml.transform.TransformerException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportFacade;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.CertificateReports;

public class CertificateValidatorTest {

	@Test
	public void test() throws JAXBException, IOException, SAXException, TransformerException {
		CertificateValidator cv = CertificateValidator.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer")));
		cv.setCertificateVerifier(new CommonCertificateVerifier());

		CertificateReports reports = cv.validate();

		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getXmlDiagnosticData());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getXmlSimpleReport());

		SimpleCertificateReportFacade simpleCertificateReportFacade = SimpleCertificateReportFacade.newFacade();
		String marshalled = simpleCertificateReportFacade.marshall(reports.getSimpleReportJaxb(), true);
		assertNotNull(marshalled);
		assertNotNull(simpleCertificateReportFacade.generateHtmlReport(marshalled));
		assertNotNull(simpleCertificateReportFacade.generateHtmlReport(reports.getSimpleReportJaxb()));
		assertNotNull(simpleCertificateReportFacade.generateHtmlBootstrap3Report(marshalled));
		assertNotNull(simpleCertificateReportFacade.generateHtmlBootstrap3Report(reports.getSimpleReportJaxb()));

		DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();
		String marshalledDetailedReport = detailedReportFacade.marshall(reports.getDetailedReportJaxb(), true);
		assertNotNull(marshalledDetailedReport);
		assertNotNull(detailedReportFacade.generateHtmlReport(marshalledDetailedReport));
		assertNotNull(detailedReportFacade.generateHtmlReport(reports.getDetailedReportJaxb()));
		assertNotNull(detailedReportFacade.generateHtmlBootstrap3Report(marshalledDetailedReport));
		assertNotNull(detailedReportFacade.generateHtmlBootstrap3Report(reports.getDetailedReportJaxb()));
	}

	@Test
	public void testCertNull() {
		NullPointerException exception = assertThrows(NullPointerException.class, () -> {
			CertificateValidator.fromCertificate(null);
		});
		assertEquals("The certificate is missing", exception.getMessage());
	}

	@Test
	public void testPolicyNull() {
		NullPointerException exception = assertThrows(NullPointerException.class, () -> {
			CertificateValidator cv = CertificateValidator.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer")));
			cv.setCertificateVerifier(new CommonCertificateVerifier());
			cv.validate(null);
		});
		assertEquals("The validation policy is missing", exception.getMessage());
	}

	@Test
	public void testCustomDate() {
		CertificateValidator cv = CertificateValidator.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer")));
		cv.setCertificateVerifier(new CommonCertificateVerifier());
		GregorianCalendar gregorianCalendar = new GregorianCalendar(2019, 1, 1);
		cv.setValidationTime(gregorianCalendar.getTime());
		CertificateReports certificateReports = cv.validate();
		DiagnosticData diagnosticData = certificateReports.getDiagnosticData();
		assertEquals(gregorianCalendar.getTime(), diagnosticData.getValidationDate());
	}

}
