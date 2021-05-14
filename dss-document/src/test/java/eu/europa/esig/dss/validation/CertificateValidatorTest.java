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

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportFacade;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.TransformerException;
import java.io.File;
import java.io.IOException;
import java.util.GregorianCalendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

		DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();
		String marshalledDetailedReport = detailedReportFacade.marshall(reports.getDetailedReportJaxb(), true);
		assertNotNull(marshalledDetailedReport);
		assertNotNull(detailedReportFacade.generateHtmlReport(marshalledDetailedReport));
		assertNotNull(detailedReportFacade.generateHtmlReport(reports.getDetailedReportJaxb()));
	}

	@Test
	public void testCertNull() {
		NullPointerException exception = assertThrows(NullPointerException.class,
				() -> CertificateValidator.fromCertificate(null));
		assertEquals("The certificate is missing", exception.getMessage());
	}

	@Test
	public void testPolicyNull() {
		CertificateValidator cv = CertificateValidator
				.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer")));
		cv.setCertificateVerifier(new CommonCertificateVerifier());
		NullPointerException exception = assertThrows(NullPointerException.class, () -> cv.validate(null));
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

	@Test
	public void testPSD2() {
		CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");

		CertificateValidator cv = CertificateValidator.fromCertificate(cert);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAIASource(null);
		cv.setCertificateVerifier(certificateVerifier);

		CertificateReports reports = cv.validate();
		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getXmlDiagnosticData());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getXmlSimpleReport());

		CertificateWrapper certificateWrapper = reports.getDiagnosticData().getUsedCertificateById(cert.getDSSIdAsString());
		assertNotNull(certificateWrapper);
		assertNotNull(certificateWrapper.getPSD2Info());
		assertNotNull(certificateWrapper.getPSD2Info().getNcaId());
		assertNotNull(certificateWrapper.getPSD2Info().getNcaName());
		assertNotNull(certificateWrapper.getPSD2Info().getRoleOfPSPNames());
		assertNotNull(certificateWrapper.getPSD2Info().getRoleOfPSPOids());
	}

	@Test
	public void qcStatementsTest() {
		CertificateValidator cv = CertificateValidator
				.fromCertificate(DSSUtils.loadCertificate(new File("src/test/resources/certificates/john_doe_tc.crt")));
		cv.setCertificateVerifier(new CommonCertificateVerifier());
		CertificateReports reports = cv.validate();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		assertEquals(3, usedCertificates.size());

		CertificateWrapper certificateWrapper = usedCertificates.get(0);
		assertTrue(certificateWrapper.isQcCompliance());
		assertFalse(certificateWrapper.isSupportedByQSCD());
		assertEquals(1, certificateWrapper.getQCTypes().size());
		assertEquals(QCType.QCT_ESIGN, certificateWrapper.getQCTypes().iterator().next());
		assertEquals(1, certificateWrapper.getQcLegislationCountryCodes().size());
		assertEquals("TC", certificateWrapper.getQcLegislationCountryCodes().iterator().next());
	}

	@Test
	public void userFriendlyIdentifierProviderTest() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/certificates/CZ.cer"));
		CertificateValidator cv = CertificateValidator.fromCertificate(certificate);
		cv.setCertificateVerifier(new CommonCertificateVerifier());
		cv.setTokenIdentifierProvider(new UserFriendlyIdentifierProvider());

		CertificateReports reports = cv.validate();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SimpleCertificateReport simpleReport = reports.getSimpleReport();

		assertEquals(3, diagnosticData.getUsedCertificates().size());
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			assertTrue(certificateWrapper.getId().contains("CERTIFICATE"));
			assertTrue(certificateWrapper.getId().contains(
					DSSUtils.replaceAllNonAlphanumericCharacters(certificateWrapper.getCommonName(), "-")));
			assertTrue(certificateWrapper.getId().contains(
					DSSUtils.formatDateWithCustomFormat(certificateWrapper.getNotBefore(), "yyyyMMdd-HHmm")));

			assertTrue(simpleReport.getCertificateIds().contains(certificateWrapper.getId()));
		}

		String certId = new UserFriendlyIdentifierProvider().getIdAsStringForToken(certificate);
		assertFalse(certId.endsWith(
				DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-hhmm")));
		assertTrue(certId.endsWith(
				DSSUtils.formatDateWithCustomFormat(certificate.getNotBefore(), "yyyyMMdd-HHmm")));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport.getXmlCertificateById(certId));
	}

}
