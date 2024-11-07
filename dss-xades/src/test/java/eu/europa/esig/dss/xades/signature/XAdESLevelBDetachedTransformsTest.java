/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPathTransform;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBDetachedTransformsTest extends PKIFactoryAccess {
	
	private static final DSSDocument document = new FileDocument("src/test/resources/sample-c14n.xml");
	
	@Test
	void canonicalizationTest() throws Exception {
		List<DSSReference> references = buildReferences(document, new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE));
		XAdESSignatureParameters signatureParameters = getSignatureParameters(references);
		
		DSSDocument signed = sign(document, signatureParameters);
		
		DiagnosticData diagnosticData = validate(signed, signatureParameters, document);
		List<SignerDataWrapper> originalDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalDocuments.size());
		SignerDataWrapper originalDoc = originalDocuments.get(0);
		
		assertArrayEquals(document.getDigestValue(originalDoc.getDigestAlgoAndValue().getDigestMethod()),
				originalDoc.getDigestAlgoAndValue().getDigestValue());
	}
	
	@Test
	void xPathTest() throws Exception {
		List<DSSReference> references = buildReferences(document, new XPathTransform("ancestor-or-self::*[@Id='dss1']"));
		XAdESSignatureParameters signatureParameters = getSignatureParameters(references);
		
		DSSDocument signed = sign(document, signatureParameters);
		
		DiagnosticData diagnosticData = validate(signed, signatureParameters, document);
		List<SignerDataWrapper> originalDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalDocuments.size());
		SignerDataWrapper originalDoc = originalDocuments.get(0);

		assertArrayEquals(document.getDigestValue(originalDoc.getDigestAlgoAndValue().getDigestMethod()),
				originalDoc.getDigestAlgoAndValue().getDigestValue());
	}
	
	@Test
	void base64Test() throws Exception {
		List<DSSReference> references = buildReferences(document, new Base64Transform());
		XAdESSignatureParameters signatureParameters = getSignatureParameters(references);
		
		Exception exception = assertThrows(IllegalArgumentException.class, () -> sign(document, signatureParameters));
		assertEquals("Reference setting is not correct! Base64 transform is not compatible with DETACHED signature format.", exception.getMessage());
	}

	@Test
	void specialCharTest() throws Exception {
		DSSDocument dssDocument = new InMemoryDocument("Hello world".getBytes(), "hello+world&%/*.xml");
		List<DSSReference> references = buildReferences(dssDocument);
		XAdESSignatureParameters signatureParameters = getSignatureParameters(references);

		DSSDocument signed = sign(dssDocument, signatureParameters);

		DiagnosticData diagnosticData = validate(signed, signatureParameters, dssDocument);
		List<SignerDataWrapper> originalDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalDocuments.size());
		SignerDataWrapper originalDoc = originalDocuments.get(0);

		assertArrayEquals(dssDocument.getDigestValue(originalDoc.getDigestAlgoAndValue().getDigestMethod()),
				originalDoc.getDigestAlgoAndValue().getDigestValue());
	}
	
	private List<DSSReference> buildReferences(DSSDocument document, DSSTransform... transforms) {

        List<DSSTransform> dssTransforms = new ArrayList<>(Arrays.asList(transforms));

		DSSReference ref1 = new DSSReference();
		ref1.setContents(document);
		ref1.setId("r-" + document.getName());
		ref1.setTransforms(dssTransforms);
		ref1.setUri(document.getName());
		ref1.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
		
		List<DSSReference> refs = new ArrayList<>();
		refs.add(ref1);
		
		return refs;
		
	}
	
	private XAdESSignatureParameters getSignatureParameters(List<DSSReference> references) {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setReferences(references);
		return signatureParameters;
	}
	
	private DSSDocument sign(DSSDocument document, XAdESSignatureParameters signatureParameters) {
		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		ToBeSigned toSign1 = service.getDataToSign(document, signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(document, signatureParameters, value);
	}
	
	private DiagnosticData validate(DSSDocument signedDocument, XAdESSignatureParameters signatureParameters, DSSDocument originalDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setDetachedContents(Collections.singletonList(originalDocument));
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertEquals(signatureParameters.getSignatureLevel(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
			if (digestMatcher.getDocumentName() != null) {
				assertEquals(digestMatcher.getUri(), digestMatcher.getDocumentName());
			}
		}
		return diagnosticData;
	}


	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
