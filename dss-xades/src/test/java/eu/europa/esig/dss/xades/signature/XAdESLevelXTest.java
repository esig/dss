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
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.xades.definition.xades132.XAdES132Paths;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelXTest extends AbstractXAdESTestSignature {

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
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_X);
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

		XAdES132Paths paths = new XAdES132Paths();

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
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());

		boolean sigTstFound = false;
		boolean sigAndRefsTstFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				assertEquals(1, timestampWrapper.getTimestampedSignedData().size());
				assertEquals(1, timestampWrapper.getTimestampedCertificates().size());
				sigTstFound = true;
			} else if (TimestampType.VALIDATION_DATA_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				assertEquals(1, timestampWrapper.getTimestampedSignedData().size());
				assertEquals(4, timestampWrapper.getTimestampedCertificates().size());
				assertEquals(1, timestampWrapper.getTimestampedOrphanCertificates().size());
				assertEquals(2, timestampWrapper.getTimestampedOrphanRevocations().size());
				sigAndRefsTstFound = true;
			}
		}
		assertTrue(sigTstFound);
		assertTrue(sigAndRefsTstFound);
	}

	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> signatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticDataWithOrphans(signatures, diagnosticData);
	}

	@Override
	protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			List<RelatedCertificateWrapper> allFoundCertificates = signatureWrapper.foundCertificates().getRelatedCertificates();
			for (RelatedCertificateWrapper foundCert : allFoundCertificates) {
//				assertEquals(0, foundCert.getOrigins().size()); // only refs + can be present in KeyInfo
				List<CertificateRefWrapper> certificateRefs = foundCert.getReferences();
				assertEquals(1, certificateRefs.size());
				CertificateRefWrapper xmlCertificateRef = certificateRefs.get(0);
				assertNotNull(xmlCertificateRef);
				assertNotNull(xmlCertificateRef.getOrigin());
			}
		}
	}

	@Override
	protected void checkNoDuplicateCompleteRevocationData(DiagnosticData diagnosticData) {
		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			List<RelatedRevocationWrapper> allFoundRevocations = signatureWrapper.foundRevocations().getRelatedRevocationData();
			for (RelatedRevocationWrapper foundRevocation : allFoundRevocations) {
				assertEquals(0, foundRevocation.getOrigins().size()); // only refs
				List<RevocationRefWrapper> revocationRefs = foundRevocation.getReferences();
				assertEquals(1, revocationRefs.size());
				RevocationRefWrapper xmlRevocationRef = revocationRefs.get(0);
				assertNotNull(xmlRevocationRef);
				assertNotNull(xmlRevocationRef.getOrigins());
			}
		}
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(2, diagnosticData.getAllOrphanRevocationReferences().size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
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

}
