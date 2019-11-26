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
package eu.europa.esig.dss.asic.xades.signature.opendocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.Before;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class OpenDocumentWithSHA3Test extends AbstractOpenDocumentTestSignature {

	public OpenDocumentWithSHA3Test(File fileToTest) {
		super(fileToTest);
	}

	private DocumentSignatureService<ASiCWithXAdESSignatureParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;

	@Before
	public void init() throws Exception {
		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		
		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getSHA3GoodTsa());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		InMemoryDocument doc = new InMemoryDocument(byteArray);

		SignedDocumentValidator validator = getValidator(doc);

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		verifyDiagnosticData(diagnosticData);
		
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		for(CertificateWrapper wrapper: usedCertificates) {
			assertEquals(DigestAlgorithm.SHA3_256, wrapper.getDigestAlgorithm());
		}
		
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		for(RevocationWrapper wrapper : allRevocationData) {
			assertEquals(DigestAlgorithm.SHA3_256, wrapper.getDigestAlgorithm());
		}
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for(TimestampWrapper wrapper : timestampList) {
			assertEquals(DigestAlgorithm.SHA3_256, wrapper.getDigestAlgorithm());
		}
	}

	@Override
	protected DocumentSignatureService<ASiCWithXAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}

}
