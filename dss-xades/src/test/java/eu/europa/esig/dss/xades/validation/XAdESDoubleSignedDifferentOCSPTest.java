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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

class XAdESDoubleSignedDifferentOCSPTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/doubleSignedTest.xml");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		
		assertEquals(2, signatureWrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationData().size());
		assertEquals(0, signatureWrapper.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, signatureWrapper.foundRevocations().getOrphanRevocationRefs().size());
		
		List<RelatedCertificateWrapper> foundCertificatesByLocation = signatureWrapper.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
		assertNotNull(foundCertificatesByLocation);
		assertEquals(2, foundCertificatesByLocation.size());
		
		SignatureWrapper signature2Wrapper = signatures.get(1);
		assertEquals(2, signature2Wrapper.foundRevocations().getRelatedRevocationData().size());
		assertEquals(0, signature2Wrapper.foundRevocations().getOrphanRevocationData().size());
		assertEquals(2, signature2Wrapper.foundRevocations().getRelatedRevocationRefs().size());
		assertEquals(0, signature2Wrapper.foundRevocations().getOrphanRevocationRefs().size());
	}

}
