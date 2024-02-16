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

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.validationreport.jaxb.SACertIDListType;
import eu.europa.esig.validationreport.jaxb.SARevIDListType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import jakarta.xml.bind.JAXBElement;
import java.io.File;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelCTest extends AbstractXAdESTestSignature {

	protected CertificateVerifier certificateVerifier;
	protected XAdESSignatureParameters signatureParameters;
	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_C);
		signatureParameters.setTokenReferencesDigestAlgorithm(DigestAlgorithm.SHA384);
		signatureParameters.setEn319132(false);

		certificateVerifier = getCompleteCertificateVerifier();
		PKIOCSPSource pkiocspSource = pkiDelegatedOCSPSource();
		certificateVerifier.setOcspSource(pkiocspSource);
		service = new XAdESService(certificateVerifier);
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
	}

	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> signatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticDataWithOrphans(signatures, diagnosticData);
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);

		AdvancedSignature advancedSignature = signatures.get(0);

		Set<CertificateRef> certificateRefs = advancedSignature.getCertificateSource().getAllCertificateRefs();
		assertTrue(Utils.isCollectionNotEmpty(certificateRefs));
		for (CertificateRef certificateRef : certificateRefs) {
			assertNotNull(certificateRef.getCertDigest());
			assertNotNull(certificateRef.getCertificateIdentifier());
		}

		List<RevocationRef<OCSP>> ocspRefs = advancedSignature.getOCSPSource().getCompleteRevocationRefs();
		List<RevocationRef<CRL>> crlRefs = advancedSignature.getCRLSource().getCompleteRevocationRefs();

		assertTrue(Utils.isCollectionNotEmpty(ocspRefs) || Utils.isCollectionNotEmpty(crlRefs));

		if (!ocspRefs.isEmpty()) {
			for (RevocationRef<OCSP> ocspRef : ocspRefs) {
				assertNotNull(ocspRef.getDigest());
				assertNotNull(ocspRef.getDigest().getAlgorithm());
				assertNotNull(ocspRef.getDigest().getValue());
			}
		}

		if (!crlRefs.isEmpty()) {
			for (RevocationRef<CRL> crlRef : crlRefs) {
				assertNotNull(crlRef.getDigest());
				assertNotNull(crlRef.getDigest().getAlgorithm());
				assertNotNull(crlRef.getDigest().getValue());
			}
		}

	}

	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		super.checkCertificates(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		FoundCertificatesProxy foundCertificates = signature.foundCertificates();
		List<RelatedCertificateWrapper> completeCertificatesRefs = foundCertificates.getRelatedCertificatesByRefOrigin(
				CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		assertEquals(3, completeCertificatesRefs.size());

		for (RelatedCertificateWrapper certificateWrapper : completeCertificatesRefs) {
			for (CertificateRefWrapper certificateRefWrapper : certificateWrapper.getReferences()) {
				assertEquals(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS, certificateRefWrapper.getOrigin());
				assertNotEquals(CertificateRefOrigin.SIGNING_CERTIFICATE, certificateRefWrapper.getOrigin());
				assertEquals(signatureParameters.getTokenReferencesDigestAlgorithm(),
						certificateRefWrapper.getDigestAlgoAndValue().getDigestMethod());
			}
		}

		List<RelatedCertificateWrapper> signingCertificatesRefs = foundCertificates.getRelatedCertificatesByRefOrigin(
				CertificateRefOrigin.SIGNING_CERTIFICATE);
		assertEquals(1, signingCertificatesRefs.size());

		for (RelatedCertificateWrapper certificateWrapper : signingCertificatesRefs) {
			for (CertificateRefWrapper certificateRefWrapper : certificateWrapper.getReferences()) {
				assertNotEquals(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS, certificateRefWrapper.getOrigin());
				assertEquals(CertificateRefOrigin.SIGNING_CERTIFICATE, certificateRefWrapper.getOrigin());
				assertEquals(signatureParameters.getSigningCertificateDigestMethod(),
						certificateRefWrapper.getDigestAlgoAndValue().getDigestMethod());
			}
		}
	}

	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		FoundRevocationsProxy foundRevocations = signature.foundRevocations();

		assertEquals(0, foundRevocations.getRelatedRevocationRefs().size());
		assertEquals(2, foundRevocations.getOrphanRevocationRefs().size());
		for (RevocationRefWrapper revocationRefWrapper: foundRevocations.getOrphanRevocationRefs()) {
			assertEquals(RevocationRefOrigin.COMPLETE_REVOCATION_REFS, revocationRefWrapper.getOrigins().get(0));
			assertEquals(signatureParameters.getTokenReferencesDigestAlgorithm(),
					revocationRefWrapper.getDigestAlgoAndValue().getDigestMethod());
		}
	}

	@Override
	protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
		super.checkNoDuplicateCompleteCertificates(diagnosticData);

		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			List<RelatedCertificateWrapper> allFoundCertificates = signatureWrapper.foundCertificates().getRelatedCertificates();
			for (RelatedCertificateWrapper foundCert : allFoundCertificates) {
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
		super.checkNoDuplicateCompleteRevocationData(diagnosticData);

		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			List<RelatedRevocationWrapper> allFoundRevocations = signatureWrapper.foundRevocations().getRelatedRevocationData();
			for (RelatedRevocationWrapper foundRevocation : allFoundRevocations) {
				assertEquals(0, foundRevocation.getOrigins().size()); // only refs
				List<RevocationRefWrapper> revocationRefs = foundRevocation.getReferences();
				assertEquals(2, revocationRefs.size());
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
	protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
		super.validateETSISignatureAttributes(signatureAttributes);

		boolean signCertRefFound = false;
		boolean completeCertRefFound = false;
		boolean completeRevocRefFound = false;

		List<JAXBElement<?>> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		for (JAXBElement<?> signatureAttributeObj : signatureAttributeObjects) {
			String xmlElementName = signatureAttributeObj.getName().getLocalPart();
			if ("SigningCertificate".equals(xmlElementName)) {
				SACertIDListType certIdList = (SACertIDListType) signatureAttributeObj.getValue();
				assertTrue(certIdList.isSigned());
				assertEquals(1, certIdList.getAttributeObject().size());
				assertEquals(1, certIdList.getAttributeObject().get(0).getVOReference().size());
				assertEquals(0, certIdList.getCertID().size());
				signCertRefFound = true;
			}
			if ("CompleteCertificateRefs".equals(xmlElementName)) {
				SACertIDListType certIdList = (SACertIDListType) signatureAttributeObj.getValue();
				assertEquals(1, certIdList.getAttributeObject().size());
				assertEquals(3, certIdList.getAttributeObject().get(0).getVOReference().size());
				assertEquals(1, certIdList.getCertID().size());
				completeCertRefFound = true;
			}
			if ("CompleteRevocationRefs".equals(xmlElementName)) {
				SARevIDListType revIdList = (SARevIDListType) signatureAttributeObj.getValue();
				assertEquals(0, revIdList.getAttributeObject().size());
				assertEquals(2, revIdList.getCRLIDOrOCSPID().size());
				completeRevocRefFound = true;
			}
		}
		assertTrue(signCertRefFound);
		assertTrue(completeCertRefFound);
		assertTrue(completeRevocRefFound);

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
