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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class PAdESOCSPSigningCertificateTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-ocsp-sign-cert.pdf"));
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		
		for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
			assertNotNull(revocationWrapper.getSigningCertificate());
			
			List<RelatedCertificateWrapper> relatedCertificates = revocationWrapper.foundCertificates().getRelatedCertificates();
			assertEquals(1, relatedCertificates.size());
			assertEquals(0, revocationWrapper.foundCertificates().getOrphanCertificates().size());
			
			RelatedCertificateWrapper relatedCertificateWrapper = relatedCertificates.get(0);
			assertEquals(1, relatedCertificateWrapper.getReferences().size());
			
			CertificateRefWrapper certificateRefWrapper = relatedCertificateWrapper.getReferences().get(0);
			assertEquals(CertificateRefOrigin.SIGNING_CERTIFICATE, certificateRefWrapper.getOrigin());
		}
	}

}
