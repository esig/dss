package eu.europa.ec.markt.dss.cookbook.example.validate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.cookbook.sources.AlwaysValidOCSPSource;
import eu.europa.ec.markt.dss.cookbook.sources.MockServiceInfo;
import eu.europa.ec.markt.dss.cookbook.sources.MockTSLCertificateSource;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.report.DetailedReport;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;

/**
 * How to validate a signature with a custom validation policy.
 */
public class ValidateSignedXmlXadesBWithCustomPolicy extends Cookbook {

	public static void main(String[] args) throws IOException {

		preparePKCS12TokenAndKey();

		final CertificateToken[] certificateChain = privateKey.getCertificateChain();
		final CertificateToken trustedCertificate = certificateChain[0];

		DSSDocument document = new FileDocument("signedXmlXadesB.xml");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();

		AlwaysValidOCSPSource ocspSource = new AlwaysValidOCSPSource();
		verifier.setOcspSource(ocspSource);

		MockTSLCertificateSource trustedCertSource = new MockTSLCertificateSource();
		ServiceInfo mockServiceInfo = new MockServiceInfo();
		trustedCertSource.addCertificate(trustedCertificate, mockServiceInfo);

		verifier.setTrustedCertSource(trustedCertSource);
		validator.setCertificateVerifier(verifier);

		Reports reports = validator.validateDocument(getPathFromResource("/constraints_0002_01_C.xml"));
		SimpleReport simpleReport = reports.getSimpleReport();
		DetailedReport detailedReport = reports.getDetailedReport();

		InputStream is = new ByteArrayInputStream(simpleReport.toByteArray());
		DSSUtils.saveToFile(is, "validationXmlXadesBWithCustomPolicy_simpleReport.xml");
		is = new ByteArrayInputStream(detailedReport.toByteArray());
		DSSUtils.saveToFile(is, "validationXmlXadesBWithCustomPolicy_detailReport.xml");
	}
}
