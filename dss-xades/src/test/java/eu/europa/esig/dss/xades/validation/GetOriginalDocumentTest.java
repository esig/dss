package eu.europa.esig.dss.xades.validation;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class GetOriginalDocumentTest {
	
	@Test
	public final void getOneOriginalDocumentFromEnvelopedSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.xml");
		
		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);
		
		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);
		signedDocument.save("C://Users/axel.abinet/Desktop/ble.xml");
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DSSDocument removeResult = validator.getOriginalDocument(reports.getDiagnosticData().getFirstSignatureId());
		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		String firstDocument = new String(canon.canonicalize(document.getBytes()));
		String secondDocument = new String(canon.canonicalize(removeResult.getBytes()));
		Assert.assertEquals(firstDocument, secondDocument);
	}
	
	@Test
	public final void getOneOriginalDocumentFromEnvelopingSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.xml");
		
		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);
		
		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DSSDocument result = validator.getOriginalDocument(reports.getDiagnosticData().getFirstSignatureId());
		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		String firstDocument = new String(canon.canonicalize(document.getBytes()));
		String secondDocument = new String(canon.canonicalize(result.getBytes()));
		Assert.assertEquals(firstDocument, secondDocument);
	}
	
	@Test(expected=DSSException.class)
	public final void getOneOriginalDocumentFromDetachedSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.xml");
		
		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);
		
		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DSSDocument result = validator.getOriginalDocument(reports.getDiagnosticData().getFirstSignatureId());
	}
	
	@Test
	public final void getTwoOriginalDocumentFromEnvelopingSignature() throws Exception {
		List<DSSReference> refs = new ArrayList<DSSReference>();
		DSSDocument doc1 = new FileDocument("src/test/resources/sample.xml");
		DSSDocument doc2 = new FileDocument("src/test/resources/sampleISO.xml");
		
		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(Transforms.TRANSFORM_BASE64_DECODE);
		transforms.add(dssTransform);
		
		DSSReference ref1 = new DSSReference();
		ref1.setContents(doc1);
		ref1.setId(doc1.getName());
		ref1.setTransforms(transforms);
		ref1.setType("text/xml");
		ref1.setUri('#'+doc1.getName());
		ref1.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		
		DSSReference ref2 = new DSSReference();
		ref2.setContents(doc2);
		ref2.setId(doc2.getName());
		ref2.setTransforms(transforms);
		ref2.setType("text/xml");
		ref2.setUri('#'+doc2.getName());
		ref2.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		
		refs.add(ref1);
		refs.add(ref2);
		
		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);
		
		ToBeSigned toSign1 = service.getDataToSign(new FileDocument("src/test/resources/empty.xml"), signatureParameters);
		SignatureValue value = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, toSign1);
		DSSDocument signedDocument = service.signDocument(doc1, signatureParameters, value);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DSSDocument result = validator.getOriginalDocument(reports.getDiagnosticData().getFirstSignatureId());
		Assert.assertNotNull(result);
		Assert.assertNotNull(result.getNextDocument());
		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		String firstDocument = new String(canon.canonicalize(doc1.getBytes()));
		String secondDocument = new String(canon.canonicalize(result.getBytes()));
		Assert.assertEquals(firstDocument, secondDocument);
		firstDocument = new String(canon.canonicalize(doc2.getBytes()));
		secondDocument = new String(canon.canonicalize(result.getNextDocument().getBytes()));
		Assert.assertEquals(firstDocument, secondDocument);
		Assert.assertNull(result.getNextDocument().getNextDocument());
	}
}
