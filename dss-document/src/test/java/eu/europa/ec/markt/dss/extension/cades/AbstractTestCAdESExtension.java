package eu.europa.ec.markt.dss.extension.cades;

import java.util.Date;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.extension.AbstractTestExtension;
import eu.europa.ec.markt.dss.mock.MockTSPSource;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.cades.CAdESService;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

public abstract class AbstractTestCAdESExtension extends AbstractTestExtension {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry entryUserA = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA1);

		DSSDocument document = new InMemoryDocument("Hello world!".getBytes(), "test.bin");

		// Sign
		SignatureParameters signatureParameters = new SignatureParameters();
		signatureParameters.setSigningCertificate(entryUserA.getCertificate());
		signatureParameters.setCertificateChain(entryUserA.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1), new Date()));

		byte[] dataToSign = service.getDataToSign(document, signatureParameters);
		byte[] signatureValue = sign(signatureParameters.getSignatureAlgorithm(), entryUserA.getPrivateKey(), dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);
		return signedDocument;
	}

	@Override
	protected DocumentSignatureService getSignatureServiceToExtend() throws Exception {
		CAdESService service = new CAdESService(new CommonCertificateVerifier());
		CertificateService certificateService = new CertificateService();
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1), new Date()));
		return service;
	}

}
