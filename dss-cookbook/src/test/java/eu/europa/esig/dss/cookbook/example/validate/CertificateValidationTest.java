package eu.europa.esig.dss.cookbook.example.validate;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.SimpleCertificateReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateValidationTest {

	@Test
	public void getCertificateStatus() {

		// See Trusted Lists loading
		CertificateSource trustedCertSource = null;
		CertificateSource adjunctCertSource = null;

		// tag::demo[]

		// Firstly, we load the certificate to validated
		CertificateToken token = DSSUtils.loadCertificate(new File("src/main/resources/keystore/ec.europa.eu.1.cer"));

		// We need a certificate verifier
		CertificateVerifier cv = new CommonCertificateVerifier();

		// We can inject several sources. eg: OCSP, CRL, AIA, trusted lists

		// Capability to download resources from AIA
		cv.setDataLoader(new CommonsDataLoader());

		// Capability to request OCSP Responders
		cv.setOcspSource(new OnlineOCSPSource());

		// Capability to download CRL
		cv.setCrlSource(new OnlineCRLSource());

		// We now add trust anchors (trusted list, keystore,...)
		cv.setTrustedCertSource(trustedCertSource);

		// We also can add missing certificates
		cv.setAdjunctCertSource(adjunctCertSource);

		// We create an instance of the CertificateValidator with the certificate
		CertificateValidator validator = CertificateValidator.fromCertificate(token);
		validator.setCertificateVerifier(cv);

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
