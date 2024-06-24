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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * How to validate a XAdES-BASELINE-B signature.
 */
public class ValidateSignedXmlXadesBTest {

	@Test
	public void validateXAdESBaselineB() throws Exception {

		// See Trusted Lists loading
		CertificateSource keystoreCertSource = new KeyStoreCertificateSource(new File("src/test/resources/self-signed-tsa.p12"), "PKCS12", "ks-password".toCharArray());
		CertificateSource adjunctCertSource = new KeyStoreCertificateSource(new File("src/test/resources/self-signed-tsa.p12"), "PKCS12", "ks-password".toCharArray());

		// tag::demo[]
		// import eu.europa.esig.dss.detailedreport.DetailedReport;
		// import eu.europa.esig.dss.diagnostic.DiagnosticData;
		// import eu.europa.esig.dss.model.DSSDocument;
		// import eu.europa.esig.dss.model.FileDocument;
		// import eu.europa.esig.dss.service.crl.OnlineCRLSource;
		// import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
		// import eu.europa.esig.dss.simplereport.SimpleReport;
		// import eu.europa.esig.dss.spi.x509.CertificateSource;
		// import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
		// import eu.europa.esig.dss.spi.validation.CertificateVerifier;
		// import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
		// import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
		// import eu.europa.esig.dss.validation.SignedDocumentValidator;
		// import eu.europa.esig.dss.validation.reports.Reports;
		// import eu.europa.esig.validationreport.jaxb.ValidationReportType;
		// import java.io.File;

		// First, we need a Certificate verifier
		CertificateVerifier cv = new CommonCertificateVerifier();

		// We can inject several sources. eg: OCSP, CRL, AIA, trusted lists

		// Capability to download resources from AIA
		cv.setAIASource(new DefaultAIASource());

		// Capability to request OCSP Responders
		cv.setOcspSource(new OnlineOCSPSource());

		// Capability to download CRL
		cv.setCrlSource(new OnlineCRLSource());
		
		// Create an instance of a trusted certificate source
		CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		// import the keystore as trusted
		trustedCertSource.importAsTrusted(keystoreCertSource);

		// Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
		// Hint : use method {@code CertificateVerifier.setTrustedCertSources(certSources)} in order to overwrite the existing list
		cv.addTrustedCertSources(trustedCertSource);

		// Additionally add missing certificates to a list of adjunct certificate sources (not trusted certificates)
		cv.addAdjunctCertSources(adjunctCertSource);

		// Here is the document to be validated (any kind of signature file)
		DSSDocument document = new FileDocument(new File("src/test/resources/signature-pool/signedXmlXadesLT.xml"));

		// We create an instance of DocumentValidator
		// It will automatically select the supported validator from the classpath
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);

		// We add the certificate verifier (which allows to verify and trust certificates)
		documentValidator.setCertificateVerifier(cv);

		// Here, everything is ready. We can execute the validation (for the example, we use the default and embedded
		// validation policy)
		Reports reports = documentValidator.validateDocument();

		// We have 4 reports
		// The diagnostic data which contains all used and static data
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		// The detailed report which is the result of the process of the diagnostic data and the validation policy
		DetailedReport detailedReport = reports.getDetailedReport();

		// The simple report is a summary of the detailed report (more user-friendly)
		SimpleReport simpleReport = reports.getSimpleReport();

		// The JAXB representation of the ETSI Validation report (ETSI TS 119 102-2)
		ValidationReportType estiValidationReport = reports.getEtsiValidationReportJaxb();

		// end::demo[]

		assertNotNull(reports);
		assertNotNull(diagnosticData);
		assertNotNull(detailedReport);
		assertNotNull(simpleReport);
		assertNotNull(estiValidationReport);
	}

}
