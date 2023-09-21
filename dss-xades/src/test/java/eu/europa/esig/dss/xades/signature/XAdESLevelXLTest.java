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

import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.xades.definition.xades132.XAdES132Path;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelXLTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_XL);
		signatureParameters.setEn319132(false);

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		Document document = DomUtils.buildDOM(byteArray);
		NodeList signaturesList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(document);
		assertEquals(1, signaturesList.getLength());

		XAdES132Path paths = new XAdES132Path();

		Node signature = signaturesList.item(0);
		NodeList signingCertificateList = DomUtils.getNodeList(signature, paths.getSigningCertificateChildren());
		assertEquals(1, signingCertificateList.getLength());

		NodeList signingCertificateV2List = DomUtils.getNodeList(signature, paths.getSigningCertificateV2Children());
		assertEquals(0, signingCertificateV2List.getLength());

		NodeList completeCertificateRefsList = DomUtils.getNodeList(signature, paths.getCompleteCertificateRefsPath());
		assertEquals(1, completeCertificateRefsList.getLength());

		NodeList completeCertificateRefsV2List = DomUtils.getNodeList(signature, paths.getCompleteCertificateRefsV2Path());
		assertEquals(0, completeCertificateRefsV2List.getLength());

		NodeList completeRevocationRefsList = DomUtils.getNodeList(signature, paths.getCompleteRevocationRefsPath());
		assertEquals(1, completeRevocationRefsList.getLength());

		NodeList sigAndRefsTimeStampList = DomUtils.getNodeList(signature, paths.getSigAndRefsTimestampPath());
		assertEquals(1, sigAndRefsTimeStampList.getLength());

		NodeList sigAndRefsTimeStampV2List = DomUtils.getNodeList(signature, paths.getSigAndRefsTimestampV2Path());
		assertEquals(0, sigAndRefsTimeStampV2List.getLength());

		NodeList certificateValuesList = DomUtils.getNodeList(signature, paths.getCertificateValuesPath());
		assertEquals(1, certificateValuesList.getLength());

		NodeList revocationValuesList = DomUtils.getNodeList(signature, paths.getRevocationValuesPath());
		assertEquals(1, revocationValuesList.getLength());
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(SignatureLevel.XAdES_XL, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
