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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.xades132.XAdES132Path;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-2257
public class XAdESLevelBWithRevocationDataOnlyTest extends AbstractXAdESTestValidation {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument("src/test/resources/sample.xml");

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		signatureParameters.bLevel().setSigningDate(new Date());

		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		certificateVerifier.setOcspSource(null);
		service = new XAdESService(certificateVerifier);
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected DSSDocument getSignedDocument() {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		Document dom = DomUtils.buildDOM(signedDocument);
		NodeList signaturesList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(dom.getDocumentElement());
		assertEquals(1, signaturesList.getLength());

		Node signature = signaturesList.item(0);
		Element unsignedSignatureProperties = DomUtils.getElement(signature,
				new XAdES132Path().getUnsignedSignaturePropertiesPath());
		assertNotNull(unsignedSignatureProperties);

		Element signatureTimeStamp = DomUtils.getElement(signature, new XAdES132Path().getSignatureTimestampPath());
		assertNotNull(signatureTimeStamp);

		unsignedSignatureProperties.removeChild(signatureTimeStamp);

		byte[] docBytesWithRemovedSignatureTst = DomUtils.serializeNode(dom);
		return new InMemoryDocument(docBytesWithRemovedSignatureTst);
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		certificateVerifier.setOcspSource(pkiOCSPSource());
		validator.setCertificateVerifier(certificateVerifier);
		return validator;
	}

	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);

		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(3, allRevocationData.size());

		boolean containsExternal = false;
		for (RevocationWrapper revocationWrapper : allRevocationData) {
			if (RevocationOrigin.EXTERNAL.equals(revocationWrapper.getOrigin())) {
				assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
				containsExternal = true;
			}
		}
		assertTrue(containsExternal);
	}

	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		FoundCertificatesProxy foundCertificates = signature.foundCertificates();
		assertEquals(2, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
		assertEquals(1, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
		// certificate for the removed timestamp
		assertEquals(1, foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
	}

	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER_WITH_CRL_AND_OCSP;
	}

}
