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
package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

public class TstWithEmptyCertificateSourceTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/tstWithEmptyCertSource.asice");
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		assertTrue(Utils.isCollectionEmpty(signatures));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getSignatures().size());
	}
	
	@Override
	protected void checkDetachedTimestamps(List<TimestampToken> detachedTimestamps) {
		super.checkDetachedTimestamps(detachedTimestamps);
		
		assertEquals(1, detachedTimestamps.size());
		TimestampToken timestampToken = detachedTimestamps.get(0);
		assertTrue(Utils.isCollectionEmpty(timestampToken.getCertificates()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		TimestampWrapper timestampWrapper = timestampList.get(0);
		
		assertTrue(timestampWrapper.isMessageImprintDataFound());
		assertTrue(timestampWrapper.isMessageImprintDataIntact());
		assertFalse(timestampWrapper.isSignatureValid());
	}
	
	@Override
	protected void checkTokens(DiagnosticData diagnosticData) {
		super.checkTokens(diagnosticData);
		
		assertEquals(0, diagnosticData.getUsedCertificates().size());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		TimestampWrapper timestampWrapper = timestampList.get(0);
		FoundCertificatesProxy foundCertificates = timestampWrapper.foundCertificates();
		
		assertTrue(Utils.isCollectionEmpty(foundCertificates.getRelatedCertificates()));
		assertEquals(1, foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}
	
	@Override
	protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
		assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
	}

}
