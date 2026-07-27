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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.validation.qwac.QWACValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class QWACValidationTest {

	@Test
	void test() {

		TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();

		AIASource aiaSource = new DefaultAIASource();
		RevocationSource<OCSP> ocspSource = new OnlineOCSPSource();
		RevocationSource<CRL> crlSource = new OnlineCRLSource();

		// We firstly need an Internet Access. Additional configuration may be required
		// (proxy,...)
		CommonsDataLoader dataLoader = new CommonsDataLoader();

		// We set an instance of TrustAllStrategy to rely on the Trusted Lists content
		// instead of the JVM trust store.
		dataLoader.setTrustStrategy(TrustAllStrategy.INSTANCE);

		// Thirdly, we need to configure the CertificateVerifier
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setTrustedCertSources(trustedListsCertificateSource); // configured trusted list certificate source
		cv.setAIASource(aiaSource); // configured AIA Access
		cv.setOcspSource(ocspSource); // configured OCSP Access
		cv.setCrlSource(crlSource); // configured CRL Access

		// tag::demo[]
		// import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
		// import eu.europa.esig.dss.validation.qwac.QWACValidator;
		// import eu.europa.esig.dss.validation.reports.CertificateReports;

		// Instantiate QWAC Validator
		QWACValidator qwacValidator = QWACValidator.fromUrl("https://www.microsec.hu");

		// Provide DataLoader.
		// If not set, NativeHTTPDataLoader will be used.
		qwacValidator.setDataLoader(dataLoader);

		// Set certificate verifier
		qwacValidator.setCertificateVerifier(cv);

		// Execute validation
		CertificateReports reports = qwacValidator.validate();
		SimpleCertificateReport simpleReport = reports.getSimpleReport();

		// Read validation status
		QWACProfile qwacProfile = simpleReport.getQWACProfile();

		// end::demo[]

		assertNotNull(qwacProfile);

		DetailedReport detailedReport = reports.getDetailedReport();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(simpleReport);
		assertNotNull(detailedReport);
		assertNotNull(diagnosticData);

		CertificateToken tlsCertificate = DSSUtils.loadCertificate(new File("src/main/resources/keystore/ec.europa.eu.1.cer"));

		// tag::demo-offline[]
		// import eu.europa.esig.dss.model.x509.CertificateToken;
		// import eu.europa.esig.dss.validation.qwac.QWACValidator;
		// import eu.europa.esig.dss.validation.reports.CertificateReports;

		qwacValidator = QWACValidator.fromUrlAndCertificate("http://nowina.lu", tlsCertificate);

		// Configure as required
		qwacValidator.setCertificateVerifier(cv);

		reports = qwacValidator.validate();

		// end::demo-offline[]

	}

}
