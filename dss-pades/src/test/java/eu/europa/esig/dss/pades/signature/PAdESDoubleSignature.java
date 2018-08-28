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
package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;

@RunWith(Parameterized.class)
public class PAdESDoubleSignature extends PKIFactoryAccess {

	@Parameters
	public static List<Object[]> data() {
		return Arrays.asList(new Object[10][0]);
	}

	public PAdESDoubleSignature() {
	}

	@Test
	public void testDoubleSignature() throws Exception {

		DSSDocument toBeSigned = new InMemoryDocument(PAdESDoubleSignature.class.getResourceAsStream("/sample.pdf"));

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports1 = validator.validateDocument();

		DiagnosticData diagnosticData1 = reports1.getDiagnosticData();
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA.toString(), diagnosticData1.getSignatureFormat(diagnosticData1.getFirstSignatureId()));

		params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setSigningCertificate(getSigningCert());
		service.setTspSource(getAlternateGoodTsa());

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);

		validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports reports2 = validator.validateDocument();
		DiagnosticData diagnosticData2 = reports2.getDiagnosticData();

		// Bug with 2 signatures which have the same ID
		List<String> signatureIdList = diagnosticData2.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData2.isBLevelTechnicallyValid(signatureId));
		}

		assertEquals(3, diagnosticData2.getTimestampIdList(diagnosticData2.getFirstSignatureId()).size());

		checkAllRevocationOnce(diagnosticData2);

		checkAllPreviousRevocationDataInNewDiagnosticData(diagnosticData1, diagnosticData2);

	}

	private void checkAllPreviousRevocationDataInNewDiagnosticData(DiagnosticData diagnosticData1, DiagnosticData diagnosticData2) {

		Set<RevocationWrapper> allRevocationData1 = diagnosticData1.getAllRevocationData();
		Set<RevocationWrapper> allRevocationData2 = diagnosticData2.getAllRevocationData();

		for (RevocationWrapper revocationWrapper : allRevocationData1) {
			boolean found = false;
			for (RevocationWrapper revocationWrapper2 : allRevocationData2) {
				if (Utils.areStringsEqual(revocationWrapper.getId(), revocationWrapper2.getId())) {
					found = true;
				}
			}
			assertTrue(found);
		}
	}

	private void checkAllRevocationOnce(DiagnosticData diagnosticData) {
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper certificateWrapper : usedCertificates) {
			if (certificateWrapper.isTrusted() || certificateWrapper.isIdPkixOcspNoCheck()) {
				continue;
			}
			int nbRevoc = certificateWrapper.getRevocationData().size();
			assertEquals("Nb revoc for cert " + certificateWrapper.getCommonName() + " = " + nbRevoc, 1, nbRevoc);
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
