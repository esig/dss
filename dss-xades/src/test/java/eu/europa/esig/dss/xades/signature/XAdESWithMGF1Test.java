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
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XAdESWithMGF1Test extends AbstractXAdESTestSignature {

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
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signatureParameters.setMaskGenerationFunction(MaskGenerationFunction.MGF1);

		service = new XAdESService(getCertificateVerifierWithMGF1());
		service.setTspSource(getPSSGoodTsa());
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper wrapper: allSignatures) {
			assertEquals(EncryptionAlgorithm.RSASSA_PSS, wrapper.getEncryptionAlgorithm());
			assertEquals(MaskGenerationFunction.MGF1, wrapper.getMaskGenerationFunction());
		}
		
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper wrapper: usedCertificates) {
			assertEquals(EncryptionAlgorithm.RSASSA_PSS, wrapper.getEncryptionAlgorithm());
			assertEquals(MaskGenerationFunction.MGF1, wrapper.getMaskGenerationFunction());
		}
		
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper wrapper : allRevocationData) {
			assertEquals(EncryptionAlgorithm.RSASSA_PSS, wrapper.getEncryptionAlgorithm());
			assertEquals(MaskGenerationFunction.MGF1, wrapper.getMaskGenerationFunction());
		}
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper wrapper : timestampList) {
			assertEquals(EncryptionAlgorithm.RSASSA_PSS, wrapper.getEncryptionAlgorithm());
			assertEquals(MaskGenerationFunction.MGF1, wrapper.getMaskGenerationFunction());
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
		return PSS_GOOD_USER;
	}

}
