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
package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cms.CMSException;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESDoubleLTATest extends PKIFactoryAccess {

	@Test
	public void doubleLTA() throws DSSException, CMSException {
		DSSDocument doc = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8));

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters params = new CAdESSignatureParameters();
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setSigningCertificate(getSigningCert());
		params.setCertificateChain(getCertificateChain());
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

		ToBeSigned dataToSign = service.getDataToSign(doc, params);

		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument ltaDoc = service.signDocument(doc, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(ltaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData1 = reports.getDiagnosticData();

		assertEquals(SignatureLevel.CAdES_BASELINE_LTA.toString(), diagnosticData1.getSignatureFormat(diagnosticData1.getFirstSignatureId()));

		checkAllRevocationOnce(diagnosticData1);

		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		CAdESSignatureParameters extendParams = new CAdESSignatureParameters();
		extendParams.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		DSSDocument doubleLtaDoc = service.extendDocument(ltaDoc, extendParams);

		validator = SignedDocumentValidator.fromDocument(doubleLtaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData2 = reports.getDiagnosticData();

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
			if (certificateWrapper.isTrusted() || certificateWrapper.isSelfSigned() || certificateWrapper.isIdPkixOcspNoCheck()) {
				continue;
			}
			int nbRevoc = certificateWrapper.getCertificateRevocationData().size();
			assertEquals("Nb revoc for cert " + certificateWrapper.getCommonName() + " = " + nbRevoc, 1, nbRevoc);
		}
		
		Set<TimestampWrapper> allTimestamps = diagnosticData.getTimestampSet();
		assertTrue(Utils.isCollectionNotEmpty(allTimestamps));
		
		for (TimestampWrapper timestamp : allTimestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				List<String> timestampedRevocationIds = timestamp.getTimestampedRevocationIds();
				assertNotNull(timestampedRevocationIds);
				assertEquals(2, timestampedRevocationIds.size());
				for (String id : timestampedRevocationIds) {
					RevocationWrapper revocation = diagnosticData.getRevocationById(id);
					assertNotNull(revocation);
				}
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
