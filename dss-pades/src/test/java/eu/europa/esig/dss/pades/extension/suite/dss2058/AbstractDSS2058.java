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
package eu.europa.esig.dss.pades.extension.suite.dss2058;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.slf4j.event.Level;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractDSS2058 extends AbstractPAdESTestValidation {
	
	private DSSDocument extendedDocument;
	
	protected abstract DSSDocument getDocumentToExtend();
	
	@BeforeEach
	public void init() {
		DSSDocument document = getDocumentToExtend();

		PAdESService service = new PAdESService(getCompositeCertificateVerifier());
		service.setTspSource(getCompositeTsa());
		
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		extendedDocument = service.extendDocument(document, signatureParameters);
	}

	@Override
	protected CertificateVerifier getCompositeCertificateVerifier() {
		CertificateVerifier completeCertificateVerifier = super.getCompositeCertificateVerifier();
		completeCertificateVerifier.setCheckRevocationForUntrustedChains(true);
		completeCertificateVerifier.setExtractPOEFromUntrustedChains(true);
		completeCertificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert(Level.WARN));
		completeCertificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert(Level.ERROR));
		completeCertificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert(Level.WARN));
		return completeCertificateVerifier;
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return extendedDocument;
	}
	
	@Override
	@RepeatedTest(10)
	public void validate() {
		super.validate();
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			if (Utils.isCollectionEmpty(certificateWrapper.getCertificateRevocationData())) {
				continue;
			}
			boolean validRevocationFound = false;
			for (CertificateRevocationWrapper certRevocationWrapper : certificateWrapper.getCertificateRevocationData()) {
				Date lastUseTime = null;
				Date poeTimeDate = null;
				for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
					for (CertificateWrapper certChainItem : timestampWrapper.getCertificateChain()) {
						if (certificateWrapper.equals(certChainItem) && (lastUseTime == null || timestampWrapper.getProductionTime().after(lastUseTime))) {
							lastUseTime = timestampWrapper.getProductionTime();
						}
					}
					List<RevocationWrapper> timestampedRevocations = timestampWrapper.getTimestampedRevocations();
					List<String> timestampedRevocationIds = timestampedRevocations.stream().map(RevocationWrapper::getId).collect(Collectors.toList());
					if (timestampedRevocationIds.contains(certRevocationWrapper.getId()) && 
							(poeTimeDate == null || timestampWrapper.getProductionTime().before(poeTimeDate))) {
						poeTimeDate = timestampWrapper.getProductionTime();
					}
				}
				assertNotNull(poeTimeDate);
				if (!validRevocationFound) {
					if (lastUseTime != null) {
						validRevocationFound = certRevocationWrapper.getProductionDate().compareTo(lastUseTime) >= 0;
					} else {
						// signature cert chain
						validRevocationFound = certRevocationWrapper.getProductionDate().compareTo(poeTimeDate) <= 0;
					}
				}
			}
			assertTrue(validRevocationFound, "Failed for certificate : " + certificateWrapper.getId());
		}
	}

}
