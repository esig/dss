package eu.europa.ec.markt.dss.cookbook.example.validate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.cookbook.sources.MockServiceInfo;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonTrustedCertificateSource;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;

/**
 * How to validate a PADES-BASELINE-B DETACHED signature.
 */
public class ValidateDetached extends Cookbook {

	public static void main(String[] args) throws IOException {

		preparePKCS12TokenAndKey();

		final X509Certificate[] certificateChain = privateKey.getCertificateChain();
		final X509Certificate trustedCertificate = certificateChain[0];

		// Already signed document
		DSSDocument document = new FileDocument("signedPdfPadesBDetached.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();

		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		ServiceInfo mockServiceInfo = new MockServiceInfo();
		commonTrustedCertificateSource.addCertificate(trustedCertificate, mockServiceInfo);
		verifier.setTrustedCertSource(commonTrustedCertificateSource);

		validator.setCertificateVerifier(verifier);

		//DOCUMENT TO SIGN
		List<DSSDocument> detachedContentsList = new ArrayList<DSSDocument>();
		String detachedFilePath = getPathFromResource("/hello-world.pdf");
		DSSDocument detachedContents = new FileDocument(detachedFilePath);
		detachedContentsList.add(detachedContents);
		validator.setDetachedContents(detachedContentsList);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SimpleReport simpleReport = reports.getSimpleReport();

		InputStream is = new ByteArrayInputStream(simpleReport.toByteArray());
		DSSUtils.saveToFile(is, "validationDetached_simpleReport.xml");
		is = new ByteArrayInputStream(diagnosticData.toByteArray());
		DSSUtils.saveToFile(is, "validationDetached_diagnosticReport.xml");

		//System.out.println(diagnosticData);
	}
}
