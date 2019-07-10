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
package eu.europa.esig.dss.asic.plugtests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.signature.UnmarshallingTester;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.SignatureCertificateSource;
import eu.europa.esig.jaxb.validationreport.SignatureValidationReportType;
import eu.europa.esig.jaxb.validationreport.SignersDocumentType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;

/**
 * This test is only to ensure that we don't have exception with valid? files
 */
@RunWith(Parameterized.class)
public class ETSISamplesValidationTest {

	@Parameters(name = "Validation {index} : {0}")
	public static Collection<Object[]> data() {
		File folder = new File("src/test/resources/plugtest");
		Collection<File> listFiles = Utils.listFiles(folder,
				new String[] { "p7", "p7b", "p7m", "p7s", "asice", "asics", "pdf", "xml", "bdoc", "csig", "xsig", "es3" }, true);
		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		for (File file : listFiles) {
			dataToRun.add(new Object[] { file });
		}
		return dataToRun;
	}

	private File fileToTest;

	public ETSISamplesValidationTest(File fileToTest) {
		this.fileToTest = fileToTest;
	}

	@Test
	public void testValidate() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(fileToTest));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		assertNotNull(reports.getXmlDiagnosticData());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getXmlSimpleReport());
		assertNotNull(reports.getXmlValidationReport());

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(detailedReport);

		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature advancedSignature : signatures) {
			assertNotNull(advancedSignature);
			SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
			assertNotNull(certificateSource);

			assertNotNull(certificateSource.getKeyInfoCertificates());
			assertNotNull(certificateSource.getSigningCertificateValues());
			assertNotNull(certificateSource.getCertificateValues());
			assertNotNull(certificateSource.getCompleteCertificateRefs());
			assertNotNull(certificateSource.getAttributeCertificateRefs());
			assertNotNull(certificateSource.getTimeStampValidationDataCertValues());
			assertTrue(certificateSource.getDSSDictionaryCertValues().isEmpty());
			assertTrue(certificateSource.getVRIDictionaryCertValues().isEmpty());

			assertNotNull(advancedSignature.getCRLSource());
			assertNotNull(advancedSignature.getOCSPSource());
		}
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport.getSignatureValidationReport();
		assertEquals(diagnosticData.getSignatures().size(), signatureValidationReports.size());
		for (SignatureValidationReportType signatureValidationReport : signatureValidationReports) {
			List<SignersDocumentType> signersDocuments = signatureValidationReport.getSignersDocument();
			assertNotNull(signersDocuments);
			assertTrue(signersDocuments.size() > 0);
		}
		
		UnmarshallingTester.unmarshallXmlReports(reports);
	}

}
