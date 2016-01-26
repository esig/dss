package eu.europa.esig.dss.xades.signature.en319132;

import java.io.File;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESSignatureEn319132_Extends {

	@Test
	public void extendsBToT() throws Exception {
		DSSDocument signedDocument = createSignedDocument(SignatureLevel.XAdES_BASELINE_B);

		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		XAdESService secondService = new XAdESService(new CommonCertificateVerifier());
		CertificateService secondCertificateService = new CertificateService();
		secondService.setTspSource(new MockTSPSource(secondCertificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256), new Date()));

		DSSDocument extendedDocument = secondService.extendDocument(signedDocument, extensionParameters);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports extendedReport = validator.validateDocument();

		Assert.assertNotNull(extendedReport);
		Assert.assertNotNull(extendedReport.getSimpleReport());
		Assert.assertEquals(extendedReport.getSimpleReport().getIndication(extendedReport.getSimpleReport().getFirstSignatureId()), Indication.INDETERMINATE);
	}

	@Test
	public void extendsTToLT() throws Exception {
		DSSDocument signedDocument = createSignedDocument(SignatureLevel.XAdES_BASELINE_T);

		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

		XAdESService secondService = new XAdESService(new CommonCertificateVerifier());
		CertificateService secondCertificateService = new CertificateService();
		secondService.setTspSource(new MockTSPSource(secondCertificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256), new Date()));

		DSSDocument extendedDocument = secondService.extendDocument(signedDocument, extensionParameters);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports extendedReport = validator.validateDocument();

		Assert.assertNotNull(extendedReport);
		Assert.assertNotNull(extendedReport.getSimpleReport());
		Assert.assertEquals(extendedReport.getSimpleReport().getIndication(extendedReport.getSimpleReport().getFirstSignatureId()), Indication.INDETERMINATE);
	}

	@Test
	public void extendsLTToLTA() throws Exception {
		DSSDocument signedDocument = createSignedDocument(SignatureLevel.XAdES_BASELINE_LT);

		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		XAdESService secondService = new XAdESService(new CommonCertificateVerifier());
		CertificateService secondCertificateService = new CertificateService();
		secondService.setTspSource(new MockTSPSource(secondCertificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256), new Date()));

		DSSDocument extendedDocument = secondService.extendDocument(signedDocument, extensionParameters);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports extendedReport = validator.validateDocument();

		Assert.assertNotNull(extendedReport);
		Assert.assertNotNull(extendedReport.getSimpleReport());
		Assert.assertEquals(extendedReport.getSimpleReport().getIndication(extendedReport.getSimpleReport().getFirstSignatureId()), Indication.INDETERMINATE);
	}

	private DSSDocument createSignedDocument(SignatureLevel level) throws Exception {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		SignerLocation location = new SignerLocation();
		location.setCountry("Luxembourg");
		location.setLocality("Kehlen");
		location.setStreet("Zone industrielle, 15");
		location.setPostalCode("L-8287");

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(level);
		signatureParameters.setEn319132(true);
		signatureParameters.bLevel().addClaimedSignerRole("Test role");
		signatureParameters.bLevel().setSignerLocation(location);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		DocumentSignatureService<XAdESSignatureParameters> service = new XAdESService(certificateVerifier);
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256), new Date()));
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports report = validator.validateDocument();

		Assert.assertNotNull(report);
		Assert.assertNotNull(report.getSimpleReport());
		Assert.assertEquals(report.getSimpleReport().getIndication(report.getSimpleReport().getFirstSignatureId()), Indication.INDETERMINATE);

		return signedDocument;
	}
}
