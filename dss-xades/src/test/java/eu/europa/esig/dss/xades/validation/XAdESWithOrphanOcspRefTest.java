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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class XAdESWithOrphanOcspRefTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/sig-with-orphan-ocsp-ref.xml");
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<OrphanRevocationWrapper> orphanRevocationData = signatureWrapper.foundRevocations().getOrphanRevocationData();
		assertEquals(3, orphanRevocationData.size());
		
		List<OrphanRevocationWrapper> ocspOrphanRevocations = signatureWrapper.foundRevocations().getOrphanRevocationsByType(RevocationType.OCSP);
		assertEquals(2, ocspOrphanRevocations.size());
		
		int containsDigest = 0;
		String noDigestOcspRefId = null;
		for (OrphanRevocationWrapper orphanRevocationWrapper : ocspOrphanRevocations) {
			List<RevocationRefWrapper> references = orphanRevocationWrapper.getReferences();
			assertEquals(1, references.size());
			
			RevocationRefWrapper revocationRefWrapper = references.get(0);
			XmlDigestAlgoAndValue digestAlgoAndValue = revocationRefWrapper.getDigestAlgoAndValue();
			if (digestAlgoAndValue != null) {
				++containsDigest;
			} else {
				assertNotNull(revocationRefWrapper.getProductionTime());
				assertNotNull(revocationRefWrapper.getResponderIdName());
				noDigestOcspRefId = orphanRevocationWrapper.getId();
			}
		}
		assertEquals(1, containsDigest);
		assertNotNull(noDigestOcspRefId);
		
		List<RevocationRefWrapper> orphanRevocationRefs = signatureWrapper.foundRevocations().getOrphanRevocationRefs();
		assertEquals(3, orphanRevocationRefs.size());
		
		List<OrphanRevocationTokenWrapper> allOrphanRevocationObjects = diagnosticData.getAllOrphanRevocationObjects();
		assertEquals(1, allOrphanRevocationObjects.size());

		OrphanRevocationTokenWrapper orphanRevocationWrapper = allOrphanRevocationObjects.get(0);
		assertEquals(noDigestOcspRefId, orphanRevocationWrapper.getId());
		
		List<OrphanRevocationTokenWrapper> allOrphanRevocationReferences = diagnosticData.getAllOrphanRevocationReferences();
		assertEquals(2, allOrphanRevocationReferences.size());
		
	}

}
