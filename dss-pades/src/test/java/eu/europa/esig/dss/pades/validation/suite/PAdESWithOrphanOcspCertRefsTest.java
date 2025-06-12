/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESWithOrphanOcspCertRefsTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades_with_orphan_ocsp_cert_refs.pdf"));
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(1, allRevocationData.size());
		
		RevocationWrapper revocationWrapper = allRevocationData.iterator().next();
		assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
		assertNotNull(revocationWrapper.foundCertificates());
		assertEquals(0, revocationWrapper.foundCertificates().getRelatedCertificates().size());
		assertEquals(1, revocationWrapper.foundCertificates().getOrphanCertificates().size());
		assertEquals(0, revocationWrapper.foundCertificates().getRelatedCertificateRefs().size());
		assertEquals(1, revocationWrapper.foundCertificates().getOrphanCertificateRefs().size());
		
		assertEquals(1, revocationWrapper.foundCertificates().getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
		
		assertNull(revocationWrapper.getSigningCertificate());
		assertTrue(Utils.isCollectionEmpty(revocationWrapper.getCertificateChain()));
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size()); // OCSPResponder
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}

}
