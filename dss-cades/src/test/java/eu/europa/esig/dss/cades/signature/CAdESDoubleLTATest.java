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

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.reports.Reports;
import org.bouncycastle.cms.CMSException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESDoubleLTATest extends AbstractCAdESTestSignature {
	
	private DSSDocument documentToSign;
	private CAdESSignatureParameters parameters;
	private CAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8));
		
		parameters = new CAdESSignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		CAdESTimestampParameters archiveTimeStampParameters = new CAdESTimestampParameters();
		archiveTimeStampParameters.setDigestAlgorithm(DigestAlgorithm.SHA384);
		parameters.setArchiveTimestampParameters(archiveTimeStampParameters);

        service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Override
	public void signAndVerify() {
		// do nothing
	}

	@Test
	public void doubleLTA() throws DSSException, CMSException {
		DSSDocument signed = sign();
		Reports reports = verify(signed);

		DiagnosticData diagnosticData1 = reports.getDiagnosticData();

		assertEquals(SignatureLevel.CAdES_BASELINE_LTA, diagnosticData1.getSignatureFormat(diagnosticData1.getFirstSignatureId()));
		assertEquals(2, diagnosticData1.getTimestampIdList(diagnosticData1.getFirstSignatureId()).size());

		checkAllRevocationOnce(diagnosticData1);

		CAdESTimestampParameters archiveTimeStampParameters = new CAdESTimestampParameters();
		archiveTimeStampParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		parameters.setArchiveTimestampParameters(archiveTimeStampParameters);

		DSSDocument doubleLtaDoc = service.extendDocument(signed, parameters);
		reports = verify(doubleLtaDoc);

		DiagnosticData diagnosticData2 = reports.getDiagnosticData();

		assertEquals(SignatureLevel.CAdES_BASELINE_LTA, diagnosticData2.getSignatureFormat(diagnosticData1.getFirstSignatureId()));
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
			assertEquals(1, nbRevoc, "Nb revoc for cert " + certificateWrapper.getCommonName() + " = " + nbRevoc);
		}

		List<TimestampWrapper> allTimestamps = diagnosticData.getTimestampList();
		assertTrue(Utils.isCollectionNotEmpty(allTimestamps));
		
		for (TimestampWrapper timestamp : allTimestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				List<RevocationWrapper> timestampedRevocations = timestamp.getTimestampedRevocations();
				assertNotNull(timestampedRevocations);
				assertEquals(2, timestampedRevocations.size());
				for (RevocationWrapper revocation : timestampedRevocations) {
					RevocationWrapper revocationWrapper = diagnosticData.getRevocationById(revocation.getId());
					assertNotNull(revocationWrapper);
				}
			}
		}
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		assertEquals(1, signatures.size());

		CAdESSignature cadesSignature = (CAdESSignature) signatures.get(0);
		Set<DigestAlgorithm> messageDigestAlgorithms = cadesSignature.getMessageDigestAlgorithms();

		assertEquals(cadesSignature.getAllTimestamps().size(), messageDigestAlgorithms.size());

		boolean sha256Found = false;
		boolean sha384Found = false;
		boolean sha512Found = false;
		for (DigestAlgorithm digestAlgorithm : messageDigestAlgorithms) {
			if (DigestAlgorithm.SHA256.equals(digestAlgorithm)) {
				sha256Found = true;
			} else if (DigestAlgorithm.SHA384.equals(digestAlgorithm)) {
				sha384Found = true;
			} else if (DigestAlgorithm.SHA512.equals(digestAlgorithm)) {
				sha512Found = true;
			}
		}
		assertTrue(sha256Found);
		assertTrue(sha384Found);
		assertEquals(cadesSignature.getAllTimestamps().size() == 3, sha512Found);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return parameters;
	}

}
