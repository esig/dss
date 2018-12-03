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
package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.transforms.Transforms;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class GetOriginalDocumentTest extends PKIFactoryAccess {

	@Test
	public final void getOneOriginalDocumentFromEnvelopedSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.xml");

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<DSSDocument> originals = validator.getOriginalDocuments(reports.getDiagnosticData().getFirstSignatureId());
		assertEquals(1, originals.size());

		DSSDocument original = originals.get(0);

		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		String firstDocument = new String(canon.canonicalize(DSSUtils.toByteArray(document)));
		String secondDocument = new String(canon.canonicalize(DSSUtils.toByteArray(original)));
		assertEquals(firstDocument, secondDocument);
	}

	@Test
	public final void getOneOriginalDocumentFromEnvelopedSignatureTwice() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.xml");

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		service = new XAdESService(getCompleteCertificateVerifier());

		dataToSign = service.getDataToSign(signedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		final DSSDocument resignedDocument = service.signDocument(signedDocument, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(resignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<String> signatureIdList = reports.getDiagnosticData().getSignatureIdList();
		assertEquals(2, signatureIdList.size());

		List<DSSDocument> originals = validator.getOriginalDocuments(signatureIdList.get(0));
		assertEquals(1, originals.size());
		DSSDocument original = originals.get(0);
		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		String firstDocument = new String(canon.canonicalize(DSSUtils.toByteArray(document)));
		String secondDocument = new String(canon.canonicalize(DSSUtils.toByteArray(original)));
		assertEquals(firstDocument, secondDocument);

		originals = validator.getOriginalDocuments(signatureIdList.get(1));
		assertEquals(1, originals.size());
		original = originals.get(0);
		canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		firstDocument = new String(canon.canonicalize(DSSUtils.toByteArray(document)));
		secondDocument = new String(canon.canonicalize(DSSUtils.toByteArray(original)));
		assertEquals(firstDocument, secondDocument);
	}

	@Test
	public final void getOneOriginalDocumentFromEnvelopingSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.xml");

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<DSSDocument> results = validator.getOriginalDocuments(reports.getDiagnosticData().getFirstSignatureId());
		assertEquals(1, results.size());

		DSSDocument dssDocument = results.get(0);

		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		String firstDocument = new String(canon.canonicalize(DSSUtils.toByteArray(document)));
		String secondDocument = new String(canon.canonicalize(DSSUtils.toByteArray(dssDocument)));
		assertEquals(firstDocument, secondDocument);
	}

	@Test
	public final void getOneOriginalDocumentFromDetachedSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.xml");

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setDetachedContents(Arrays.asList(document));
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<DSSDocument> results = validator.getOriginalDocuments(reports.getDiagnosticData().getFirstSignatureId());
		assertEquals(1, results.size());

		DSSDocument dssDocument = results.get(0);

		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		String firstDocument = new String(canon.canonicalize(DSSUtils.toByteArray(document)));
		String secondDocument = new String(canon.canonicalize(DSSUtils.toByteArray(dssDocument)));
		assertEquals(firstDocument, secondDocument);
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
		ref1.setId("r-" + doc1.getName());
		ref1.setTransforms(transforms);
		ref1.setType(Reference.OBJECT_URI);
		ref1.setUri('#' + doc1.getName());
		ref1.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);

		DSSReference ref2 = new DSSReference();
		ref2.setContents(doc2);
		ref2.setId("r-" + doc2.getName());
		ref2.setTransforms(transforms);
		ref2.setType(Reference.OBJECT_URI);
		ref2.setUri('#' + doc2.getName());
		ref2.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);

		refs.add(ref1);
		refs.add(ref2);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		ToBeSigned toSign1 = service.getDataToSign(new FileDocument("src/test/resources/empty.xml"), signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(doc1, signatureParameters, value);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<DSSDocument> results = validator.getOriginalDocuments(reports.getDiagnosticData().getFirstSignatureId());
		assertEquals(2, results.size());

		DSSDocument orig1 = results.get(0);
		DSSDocument orig2 = results.get(1);

		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		String firstDocument = new String(canon.canonicalize(DSSUtils.toByteArray(doc1)));
		String secondDocument = new String(canon.canonicalize(DSSUtils.toByteArray(orig1)));
		assertEquals(firstDocument, secondDocument);

		firstDocument = new String(canon.canonicalize(DSSUtils.toByteArray(doc2)));
		secondDocument = new String(canon.canonicalize(DSSUtils.toByteArray(orig2)));
		assertEquals(firstDocument, secondDocument);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
