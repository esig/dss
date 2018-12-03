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
package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.transforms.Transforms;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBWith2ReferencesTest extends PKIFactoryAccess {

	private static String FILE1 = "src/test/resources/sample.xml";
	private static String FILE2 = "src/test/resources/sampleISO.xml";

	@Test
	public void test1() throws Exception {
		List<DSSReference> refs = new ArrayList<DSSReference>();
		DSSDocument doc1 = new FileDocument(FILE1);
		DSSDocument doc2 = new FileDocument(FILE2);

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
		DSSDocument result = service.signDocument(doc1, signatureParameters, value);
//		result.save("target/test.xml");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(result);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(2, Utils.collectionSize(signatureWrapper.getSignatureScopes()));

		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		assertEquals(getCertificateChain().length, signatureCertificateChain.size());
		assertEquals(signatureParameters.getSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void multiDocsEnveloping() throws Exception {
		List<DSSDocument> docs = new ArrayList<DSSDocument>();
		docs.add(new FileDocument(FILE1));
		docs.add(new FileDocument(FILE2));

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		ToBeSigned toSign1 = service.getDataToSign(docs, signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument result = service.signDocument(docs, signatureParameters, value);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(result);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(2, Utils.collectionSize(signatureWrapper.getSignatureScopes()));

		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		assertEquals(getCertificateChain().length, signatureCertificateChain.size());
		assertEquals(signatureParameters.getSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void multiDocsDetached() throws Exception {
		List<DSSDocument> docs = new ArrayList<DSSDocument>();
		docs.add(new FileDocument(FILE1));
		docs.add(new FileDocument(FILE2));

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		ToBeSigned toSign1 = service.getDataToSign(docs, signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument result = service.signDocument(docs, signatureParameters, value);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(result);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(docs);
		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(2, Utils.collectionSize(signatureWrapper.getSignatureScopes()));

		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		assertEquals(getCertificateChain().length, signatureCertificateChain.size());
		assertEquals(signatureParameters.getSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void test2() throws Exception {
		DSSDocument doc1 = new FileDocument(FILE1);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		ToBeSigned toSign1 = service.getDataToSign(doc1, signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument result = service.signDocument(doc1, signatureParameters, value);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(result);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(1, Utils.collectionSize(signatureWrapper.getSignatureScopes()));

		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		assertEquals(getCertificateChain().length, signatureCertificateChain.size());
		assertEquals(signatureParameters.getSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
