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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import org.apache.xml.security.signature.Reference;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBBase64TransformTest extends PKIFactoryAccess {
	
	private static final DSSDocument document = new FileDocument("src/test/resources/sample.xml");
	
	@Test
	public void test() {
		
		List<DSSTransform> transforms = new ArrayList<>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		
		List<DSSReference> refs = buildReferences(document, transforms);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);

		signAndValidate(document, signatureParameters);
		
	}
	
	@Test
	public void imageSignTest() {
		
		String imageFileName = "sample.png";
		DSSDocument image = new FileDocument("src/test/resources/" + imageFileName);
		
		List<DSSTransform> transforms = new ArrayList<>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		
		List<DSSReference> refs = buildReferences(image, transforms);
		
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);

		DSSDocument signedDocument = sign(image, signatureParameters);
		DiagnosticData diagnosticData = validate(signedDocument, signatureParameters);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertNotNull(digestMatchers);
		
		boolean objectFound = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.OBJECT.equals(digestMatcher.getType())) {
				DigestAlgorithm digestAlgorithm = digestMatcher.getDigestMethod();
				assertEquals(image.getDigest(digestAlgorithm), Utils.toBase64(digestMatcher.getDigestValue()));
				objectFound = true;
			}
		}
		assertTrue(objectFound);
		
		String originalBase64 = Utils.toBase64(DSSUtils.toByteArray(image));
		assertTrue(Utils.isStringNotBlank(originalBase64));
		Document documentDom = DomUtils.buildDOM(signedDocument);
		Element objectElement = DomUtils.getElementById(documentDom, imageFileName);
		assertNotNull(objectElement);
		assertEquals(originalBase64, objectElement.getTextContent());
		
	}
	
	@Test
	public void embedXmlWithBase64Test() {
		List<DSSTransform> transforms = new ArrayList<>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);

		List<DSSReference> refs = buildReferences(document, transforms);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setEmbedXML(true);
		signatureParameters.setReferences(refs);
		Exception exception = assertThrows(DSSException.class, () -> signAndValidate(document, signatureParameters));
		assertEquals("Reference setting is not correct! The embedXML(true) parameter is not compatible with base64 transform.", exception.getMessage());
	}
	
	@Test
	public void envelopedBase64TransformTest() {
		List<DSSTransform> transforms = new ArrayList<>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);

		List<DSSReference> refs = buildReferences(document, transforms);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);
		Exception exception = assertThrows(DSSException.class, () -> signAndValidate(document, signatureParameters));
		assertEquals("Reference setting is not correct! Base64 transform is not compatible with ENVELOPED signature format.", exception.getMessage());		
	}
	
	@Test
	public void base64WithOtherReferencesTest() {
		List<DSSTransform> transforms = new ArrayList<>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		CanonicalizationTransform canonicalizationTransform = new CanonicalizationTransform(
				CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
		transforms.add(canonicalizationTransform);

		List<DSSReference> refs = buildReferences(document, transforms);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);
		Exception exception = assertThrows(DSSException.class, () -> signAndValidate(document, signatureParameters));
		assertEquals("Reference setting is not correct! Base64 transform cannot be used with other transformations.", exception.getMessage());		
	}
	
	@Test
	public void doubleBase64TransformTest() {
		List<DSSTransform> transforms = new ArrayList<>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);
		Base64Transform dssTransform2 = new Base64Transform();
		transforms.add(dssTransform2);

		List<DSSReference> refs = buildReferences(document, transforms);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);
		Exception exception = assertThrows(DSSException.class, () -> signAndValidate(document, signatureParameters));
		assertEquals("Reference setting is not correct! Base64 transform cannot be used with other transformations.", exception.getMessage());		
	}
	
	@Test
	public void manifestWithBase64Test() {
		List<DSSDocument> documents = new ArrayList<>();
		documents.add(new FileDocument("src/test/resources/sample.png"));
		documents.add(new FileDocument("src/test/resources/sample.txt"));
		documents.add(new FileDocument("src/test/resources/sample.xml"));
		ManifestBuilder builder = new ManifestBuilder(DigestAlgorithm.SHA512, documents);

		DSSDocument documentToSign = builder.build();

		List<DSSTransform> transforms = new ArrayList<>();
		Base64Transform dssTransform = new Base64Transform();
		transforms.add(dssTransform);

		List<DSSReference> refs = buildReferences(document, transforms);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(refs);
		signatureParameters.setManifestSignature(true);
		Exception exception = assertThrows(DSSException.class,
				() -> signAndValidate(documentToSign, signatureParameters));
		assertEquals("Reference setting is not correct! Manifest signature is not compatible with base64 transform.", exception.getMessage());	
	}
	
	private List<DSSReference> buildReferences(DSSDocument document, List<DSSTransform> transforms) {

		DSSReference ref1 = new DSSReference();
		ref1.setContents(document);
		ref1.setId("r-" + document.getName());
		ref1.setTransforms(transforms);
		ref1.setType(Reference.OBJECT_URI);
		ref1.setUri('#' + document.getName());
		ref1.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		
		List<DSSReference> refs = new ArrayList<>();
		refs.add(ref1);
		
		return refs;
		
	}
	
	private DiagnosticData signAndValidate(DSSDocument document, XAdESSignatureParameters signatureParameters) {
		DSSDocument result = sign(document, signatureParameters);
		return validate(result, signatureParameters);
	}
	
	private DSSDocument sign(DSSDocument document, XAdESSignatureParameters signatureParameters) {
		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		ToBeSigned toSign1 = service.getDataToSign(document, signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(document, signatureParameters, value);
	}
	
	private DiagnosticData validate(DSSDocument signedDocument, XAdESSignatureParameters signatureParameters) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertEquals(signatureParameters.getSignatureLevel(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
		return diagnosticData;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
