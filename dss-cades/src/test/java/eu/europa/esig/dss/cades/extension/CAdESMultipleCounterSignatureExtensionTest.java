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
package eu.europa.esig.dss.cades.extension;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESMultipleCounterSignatureExtensionTest extends AbstractCAdESTestExtension {
	
	private CertificateVerifier certificateVerifier;
	private CAdESService service;
	
	@BeforeEach
	public void init() {
		certificateVerifier = getCompleteCertificateVerifier();
		certificateVerifier.setCheckRevocationForUntrustedChains(true);
		certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert(Level.WARN));
		certificateVerifier.setAlertOnInvalidTimestamp(new LogOnStatusAlert(Level.WARN));
		certificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert(Level.WARN));
		certificateVerifier.setAlertOnExpiredSignature(new LogOnStatusAlert(Level.WARN));
		
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		CertificateToken rootCert = DSSUtils.loadCertificateFromBase64EncodedString("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");
		commonTrustedCertificateSource.addCertificate(rootCert);
		certificateVerifier.addTrustedCertSources(commonTrustedCertificateSource);
		service = new CAdESService(certificateVerifier);
		service.setTspSource(getUsedTSPSourceAtExtensionTime());
	}
	
	@Test
	@Override
	public void extendAndVerify() throws Exception {
		DSSDocument signedDocument = new FileDocument("src/test/resources/validation/signedFile.pdf.p7s");
		DSSDocument extendedDocument = extendSignature(signedDocument);
		verify(extendedDocument);
	}
	
	@Override
	protected CAdESService getSignatureServiceToExtend() {
		return service;
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setCertificateVerifier(certificateVerifier);
		return validator;
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(getFinalSignatureLevel(), diagnosticData.getFirstSignatureFormat()); 
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		int signatureTstCounter = 0;
		int archiveTstCounter = 0;
		
		boolean oneSignatureFound = false;
		boolean twoSignaturesFound = false;
		boolean threeSignaturesFound = false;
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(6, timestampList.size());
		
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++signatureTstCounter;
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++archiveTstCounter;
				
				List<SignatureWrapper> timestampedSignatures = timestampWrapper.getTimestampedSignatures();
				if (timestampedSignatures.size() == 1) {
					oneSignatureFound = true;
				} else if (timestampedSignatures.size() == 2) {
					twoSignaturesFound = true;
				} else if (timestampedSignatures.size() == 3) {
					threeSignaturesFound = true;
				}
				
				for (SignatureWrapper signatureWrapper : timestampedSignatures) {
					SignatureWrapper masterSignature = signatureWrapper.getParent();
					if (masterSignature != null) {
						assertTrue(timestampedSignatures.contains(masterSignature));
					}
					Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignaturesForMasterSignature(signatureWrapper);
					for (SignatureWrapper counterSignature : counterSignatures) {
						assertTrue(timestampedSignatures.contains(counterSignature));
					}
				}
			}
		}
		
		assertEquals(3, signatureTstCounter);
		assertEquals(3, archiveTstCounter);
		assertTrue(oneSignatureFound);
		assertTrue(twoSignaturesFound);
		assertTrue(threeSignaturesFound);
	}

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.CAdES_BASELINE_LTA;
	}

}
