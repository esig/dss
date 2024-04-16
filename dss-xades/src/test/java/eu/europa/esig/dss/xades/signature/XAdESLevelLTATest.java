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

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.OriginalIdentifierProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelLTATest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setTokenIdentifierProvider(new OriginalIdentifierProvider());
		return validator;
	}

	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

		assertTrue(Utils.isCollectionNotEmpty(advancedSignatures));
		for (AdvancedSignature advancedSignature : advancedSignatures) {
			SignatureWrapper signature = diagnosticData.getSignatureById(advancedSignature.getId());
			assertNotNull(signature);

			List<CertificateToken> certificates = advancedSignature.getCertificates();
			List<String> certIds = certificates.stream().map(CertificateToken::getDSSIdAsString).collect(Collectors.toList());
			assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getUsedCertificates()));
			for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
				assertTrue(certIds.contains(certificateWrapper.getId()));
			}

			Set<RevocationToken<CRL>> crlTokens = advancedSignature.getCRLSource().getAllRevocationTokens();
			List<String> crlIds = crlTokens.stream().map(RevocationToken::getDSSIdAsString).collect(Collectors.toList());
			Set<RevocationToken<OCSP>> ocspTokens = advancedSignature.getOCSPSource().getAllRevocationTokens();
			List<String> ocspIds = ocspTokens.stream().map(RevocationToken::getDSSIdAsString).collect(Collectors.toList());
			Set<String> revocIds = new HashSet<>();
			revocIds.addAll(crlIds);
			revocIds.addAll(ocspIds);
			assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getAllRevocationData()));
			for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
				assertTrue(revocIds.contains(revocationWrapper.getId()));
			}

			List<TimestampToken> timestamps = advancedSignature.getAllTimestamps();
			List<String> tstIds = timestamps.stream().map(TimestampToken::getDSSIdAsString).collect(Collectors.toList());
			assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getTimestampList()));
			for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
				assertTrue(tstIds.contains(timestampWrapper.getId()));
			}

			List<SignatureScope> signatureScopes = advancedSignature.getSignatureScopes();
			List<String> ssIds = signatureScopes.stream().map(SignatureScope::getDSSIdAsString).collect(Collectors.toList());
			assertTrue(Utils.isCollectionNotEmpty(advancedSignature.getSignatureScopes()));
			for (SignerDataWrapper signerDataWrapper: diagnosticData.getOriginalSignerDocuments()) {
				assertTrue(ssIds.contains(signerDataWrapper.getId()));
			}

		}
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		assertEquals(2, diagnosticData.getTimestampList().size());
		boolean sigTstFound = false;
		boolean arcTstFound = false;
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(0, timestampWrapper.getTimestampScopes().size());
				assertEquals(1, timestampWrapper.getTimestampedSignedData().size());
				sigTstFound = true;
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampScopes().size());
				assertEquals(1, timestampWrapper.getTimestampedSignedData().size());
				arcTstFound = true;
			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper wrapper: allSignatures) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
			assertNull(wrapper.getMaskGenerationFunction());
		}

		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper wrapper: usedCertificates) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
			assertNull(wrapper.getMaskGenerationFunction());
		}

		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper wrapper : allRevocationData) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
			assertNull(wrapper.getMaskGenerationFunction());
		}

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper wrapper : timestampList) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
			assertNull(wrapper.getMaskGenerationFunction());
		}
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
