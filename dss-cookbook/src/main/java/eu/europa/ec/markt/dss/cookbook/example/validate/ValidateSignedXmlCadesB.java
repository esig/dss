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
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.report.DetailedReport;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;

/**
 * How to validate a CADES-BASELINE-B envelopping signature.
 */
public class ValidateSignedXmlCadesB extends Cookbook {

	public static void main(String[] args) throws IOException {

		preparePKCS12TokenAndKey();

		final X509Certificate[] certificateChain = privateKey.getCertificateChain();
		final X509Certificate trustedCertificate = certificateChain[0];

		DSSDocument document = new FileDocument("signedXmlCadesBEnvelopping");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		System.out.println(validator.getClass());

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		AlwaysValidOCSPSource ocspSource = new AlwaysValidOCSPSource();
		verifier.setOcspSource(ocspSource);
		/**
		 * This Trusted List Certificates Source points to
		 * "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml"
		 */
		MockTSLCertificateSource trustedCertSource = new MockTSLCertificateSource();
		ServiceInfo mockServiceInfo = new MockServiceInfo();
		trustedCertSource.addCertificate(trustedCertificate, mockServiceInfo);
		verifier.setTrustedCertSource(trustedCertSource);

		validator.setCertificateVerifier(verifier);

		Reports reports = validator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		DetailedReport detailReport = reports.getDetailedReport();

		InputStream is = new ByteArrayInputStream(simpleReport.toByteArray());
		DSSUtils.saveToFile(is, "validationXmlCadesB_simpleReport.xml");

		is = new ByteArrayInputStream(detailReport.toByteArray());
		DSSUtils.saveToFile(is, "validationXmlCadesB_detailReport.xml");
	}
}
