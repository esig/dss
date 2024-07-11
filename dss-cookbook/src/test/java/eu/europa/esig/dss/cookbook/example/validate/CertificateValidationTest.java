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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CertificateValidationTest {

	@Test
	void getCertificateStatus() {

		// tag::demo[]
		// import eu.europa.esig.dss.detailedreport.DetailedReport;
		// import eu.europa.esig.dss.diagnostic.DiagnosticData;
		// import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
		// import eu.europa.esig.dss.model.x509.CertificateToken;
		// import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
		// import eu.europa.esig.dss.spi.DSSUtils;
		// import eu.europa.esig.dss.validation.CertificateValidator;
		// import eu.europa.esig.dss.spi.validation.CertificateVerifier;
		// import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
		// import eu.europa.esig.dss.validation.reports.CertificateReports;
		// import java.io.File;

		// Firstly, we load the certificate to be validated
		CertificateToken token = DSSUtils.loadCertificate(new File("src/main/resources/keystore/ec.europa.eu.1.cer"));

		// We need a certificate verifier and configure it  (see specific chapter about the CertificateVerifier configuration)
		CertificateVerifier cv = new CommonCertificateVerifier();

		// We create an instance of the CertificateValidator with the certificate
		CertificateValidator validator = CertificateValidator.fromCertificate(token);
		validator.setCertificateVerifier(cv);
		
		// Allows specifying which tokens need to be extracted in the diagnostic data (Base64).
		// Default : NONE)
		validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_REVOCATION_DATA);

		// We execute the validation
		CertificateReports certificateReports = validator.validate();

		// We have 3 reports
		// The diagnostic data which contains all used and static data
		DiagnosticData diagnosticData = certificateReports.getDiagnosticData();

		// The detailed report which is the result of the process of the diagnostic data and the validation policy
		DetailedReport detailedReport = certificateReports.getDetailedReport();

		// The simple report is a summary of the detailed report or diagnostic data (more user-friendly)
		SimpleCertificateReport simpleReport = certificateReports.getSimpleReport();

		// end::demo[]

		assertNotNull(certificateReports);
		assertNotNull(diagnosticData);
		assertNotNull(detailedReport);
		assertNotNull(simpleReport);

	}
}
