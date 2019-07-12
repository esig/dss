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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;
import java.util.Set;

import org.junit.Before;

import eu.europa.esig.dss.CertificateRef;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelCTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_C);
		signatureParameters.setEn319132(false);

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);

		AdvancedSignature advancedSignature = signatures.get(0);

		List<CertificateRef> certificateRefs = advancedSignature.getCertificateRefs();
		assertTrue(Utils.isCollectionNotEmpty(certificateRefs));
		for (CertificateRef certificateRef : certificateRefs) {
			assertNotNull(certificateRef.getCertDigest());
			assertNotNull(certificateRef.getIssuerInfo());
		}

		List<OCSPRef> ocspRefs = advancedSignature.getCompleteRevocationOCSPReferences();
		List<CRLRef> crlRefs = advancedSignature.getCompleteRevocationCRLReferences();

		assertTrue(Utils.isCollectionNotEmpty(ocspRefs) || Utils.isCollectionNotEmpty(crlRefs));

		if (!ocspRefs.isEmpty()) {
			for (OCSPRef ocspRef : ocspRefs) {
				assertNotNull(ocspRef.getDigest());
				assertNotNull(ocspRef.getDigest().getAlgorithm());
				assertNotNull(ocspRef.getDigest().getValue());
			}
		}

		if (!crlRefs.isEmpty()) {
			for (CRLRef crlRef : crlRefs) {
				assertNotNull(crlRef.getDigest());
				assertNotNull(crlRef.getDigest().getAlgorithm());
				assertNotNull(crlRef.getDigest().getValue());
			}
		}

	}

	@Override
	protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			List<XmlFoundCertificate> allFoundCertificates = signatureWrapper.getAllFoundCertificates();
			for (XmlFoundCertificate foundCert : allFoundCertificates) {
//				assertEquals(0, foundCert.getOrigins().size()); // only refs + can be present in KeyInfo
				List<XmlCertificateRef> certificateRefs = foundCert.getCertificateRefs();
				assertEquals(1, certificateRefs.size());
				XmlCertificateRef xmlCertificateRef = certificateRefs.get(0);
				assertNotNull(xmlCertificateRef);
				assertNotNull(xmlCertificateRef.getOrigin());
			}
		}
	}

	@Override
	protected void checkNoDuplicateCompleteRevocationData(DiagnosticData diagnosticData) {
		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			List<XmlFoundRevocation> allFoundRevocations = signatureWrapper.getAllFoundRevocations();
			for (XmlFoundRevocation foundRevocation : allFoundRevocations) {
				assertEquals(0, foundRevocation.getOrigins().size()); // only refs
				List<XmlRevocationRef> revocationRefs = foundRevocation.getRevocationRefs();
				assertEquals(1, revocationRefs.size());
				XmlRevocationRef xmlRevocationRef = revocationRefs.get(0);
				assertNotNull(xmlRevocationRef);
				assertNotNull(xmlRevocationRef.getOrigins());
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
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
