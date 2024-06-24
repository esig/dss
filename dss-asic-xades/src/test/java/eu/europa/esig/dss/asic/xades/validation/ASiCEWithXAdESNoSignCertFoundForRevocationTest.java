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
package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

public class ASiCEWithXAdESNoSignCertFoundForRevocationTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-A-EE_AS-6.asice");
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(1, allRevocationData.size());
		
		RevocationWrapper revocationWrapper = allRevocationData.iterator().next();
		assertNull(revocationWrapper.getSigningCertificate());
		assertFalse(revocationWrapper.isSignatureValid());
		
		FoundCertificatesProxy foundCertificates = revocationWrapper.foundCertificates();
		assertTrue(Utils.isCollectionEmpty(foundCertificates.getRelatedCertificates()));
		assertEquals(foundCertificates.getOrphanCertificates().size(), foundCertificates.getOrphanCertificateRefs().size());
		
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		RevocationWrapper revocationWrapper = allRevocationData.iterator().next();
		assertEquals(1, revocationWrapper.foundCertificates().getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}
	
}
