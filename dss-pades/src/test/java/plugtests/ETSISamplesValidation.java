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
package plugtests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.test.signature.UnmarshallingTester;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

/**
 * This test is only to ensure that we don't have exception with valid? files
 */
public class ETSISamplesValidation {

	public static Stream<Arguments> data() throws IOException {

		// We use this file because File.listFiles() doesn't work from another jar
		String listFiles = "/plugtest/plugtest_files.txt";

		Collection<Arguments> dataToRun = new ArrayList<>();
		try (BufferedReader br = new BufferedReader(
				new InputStreamReader(ETSISamplesValidation.class.getResourceAsStream(listFiles)))) {
			String filepath;
			while ((filepath = br.readLine()) != null) {
				dataToRun.add(
						Arguments.of(new InMemoryDocument(ETSISamplesValidation.class.getResourceAsStream(filepath), filepath)));
			}

		}
		return dataToRun.stream();
	}

	@ParameterizedTest(name = "Validation {index}")
	@MethodSource("data")
	public void testValidate(DSSDocument doc) {
		SignedDocumentValidator validator = new PDFDocumentValidator(doc);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

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
			assertTrue(certificateSource.getCertificateValues().isEmpty());
			assertTrue(certificateSource.getAttributeCertificateRefs().isEmpty());
			assertTrue(certificateSource.getTimeStampValidationDataCertValues().isEmpty());
			assertNotNull(certificateSource.getDSSDictionaryCertValues());
			assertNotNull(certificateSource.getVRIDictionaryCertValues());

			assertNotNull(advancedSignature.getCRLSource());
			assertNotNull(advancedSignature.getOCSPSource());
		}

		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		assertNotNull(etsiValidationReport);
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReport
				.getSignatureValidationReport();
		if (!diagnosticData.getSignatures().isEmpty()) {
			assertEquals(diagnosticData.getSignatures().size(), signatureValidationReports.size());
			for (SignatureValidationReportType signatureValidationReport : signatureValidationReports) {
				List<SignersDocumentType> signersDocuments = signatureValidationReport.getSignersDocument();
				assertNotNull(signersDocuments);
				assertEquals(1, signersDocuments.size());
			}
		}
		UnmarshallingTester.unmarshallXmlReports(reports);
	}

}
