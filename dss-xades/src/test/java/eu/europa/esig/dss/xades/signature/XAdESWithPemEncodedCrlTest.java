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

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.bouncycastle.asn1.BERTags;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
public class XAdESWithPemEncodedCrlTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private static Stream<Arguments> data() {
		Object[] objects = { SignatureLevel.XAdES_C, SignatureLevel.XAdES_X, SignatureLevel.XAdES_XL, SignatureLevel.XAdES_A, 
				SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T, SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA };

		Collection<Arguments> dataToRun = new ArrayList<>();
		for (Object obj : objects) {
			dataToRun.add(Arguments.of(obj));
		}
		return dataToRun.stream();
	}

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument("src/test/resources/sample.xml");

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@ParameterizedTest(name = "SignatureLevel {index} : {0}")
	@MethodSource("data")
	public void test(SignatureLevel level) {
		signatureParameters.setSignatureLevel(level);
		super.signAndVerify();
	}
	
	@Override
	public void signAndVerify() {
		// do nothing
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(1, signatures.size());
		AdvancedSignature advancedSignature = signatures.get(0);
		OfflineRevocationSource<CRL> crlSource = advancedSignature.getCRLSource();
		Set<EncapsulatedRevocationTokenIdentifier<CRL>> allRevocationBinaries = crlSource.getAllRevocationBinaries();
		for (EncapsulatedRevocationTokenIdentifier<CRL> identifier : allRevocationBinaries) {
			assertTrue(isDerEncoded(identifier.getBinaries()));
		}
	}
	
	private boolean isDerEncoded(byte[] binaries) {
		return binaries != null && binaries.length > 0 && (BERTags.SEQUENCE | BERTags.CONSTRUCTED) == binaries[0];
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(signatureParameters.getSignatureLevel(), signature.getSignatureFormat());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		if (SignatureLevel.XAdES_C.equals(signatureParameters.getSignatureLevel()) || 
				SignatureLevel.XAdES_X.equals(signatureParameters.getSignatureLevel())) {
			assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
			assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
			assertEquals(0, diagnosticData.getAllOrphanCertificateReferences().size());
			assertEquals(2, diagnosticData.getAllOrphanRevocationReferences().size());
		} else if (SignatureLevel.XAdES_A.equals(signatureParameters.getSignatureLevel())) {
			// skip (result is based on OCSP update in cache)
		} else {
			super.checkOrphanTokens(diagnosticData);
		}
	}

	@Override
	protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
		if (SignatureLevel.XAdES_C.equals(signatureParameters.getSignatureLevel()) || 
				SignatureLevel.XAdES_X.equals(signatureParameters.getSignatureLevel())) {
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
		} else {
			super.checkNoDuplicateCompleteCertificates(diagnosticData);
		}
	}

	@Override
	protected void checkNoDuplicateCompleteRevocationData(DiagnosticData diagnosticData) {
		if (SignatureLevel.XAdES_C.equals(signatureParameters.getSignatureLevel()) || 
				SignatureLevel.XAdES_X.equals(signatureParameters.getSignatureLevel())) {
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
		} else {
			super.checkNoDuplicateCompleteRevocationData(diagnosticData);
		}
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
		return GOOD_USER_WITH_PEM_CRL;
	}
	
}
