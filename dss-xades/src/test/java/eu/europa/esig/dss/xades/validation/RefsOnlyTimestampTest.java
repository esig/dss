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
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.HashSet;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.spi.SignatureCertificateSource;

public class RefsOnlyTimestampTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/signing-cert-multiple-refs-sig.xml");
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampList.get(0).getType());
		
		int signatureTimestampCounter = 0;
		int refsOnlyTimestampCounter = 0;
		boolean coversSignature = false;
		boolean coversTimestamp = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				signatureTimestampCounter++;
			} else if (TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP.equals(timestampWrapper.getType())) {
				List<XmlTimestampedObject> timestampedObjects = timestampWrapper.getTimestampedObjects();
				assertEquals(6, timestampedObjects.size());
				assertDoesNotContainDuplicates(timestampedObjects);
				
				for (XmlTimestampedObject timestampedReference : timestampedObjects) {
					if (diagnosticData.getSignatureIdList().contains(timestampedReference.getToken().getId())) {
						coversSignature = true;
					}
					if (diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId()).contains(timestampedReference.getToken().getId())) {
						coversTimestamp = true;
					}
				}
				
				refsOnlyTimestampCounter++;
			}
		}
		
		assertEquals(1, signatureTimestampCounter);
		assertEquals(1, refsOnlyTimestampCounter);
		assertFalse(coversSignature);
		assertFalse(coversTimestamp);
	}
	
	private void assertDoesNotContainDuplicates(List<XmlTimestampedObject> timestampedObjects) {
		HashSet<XmlTimestampedObject> timestampedObjectsSet = new HashSet<>(timestampedObjects);
		assertEquals(timestampedObjectsSet.size(), timestampedObjects.size());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> signatures, DiagnosticData diagnosticData) {
		AdvancedSignature advancedSignature = signatures.get(0);
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(advancedSignature.getId());

		SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		
		assertEquals(certificateSource.getAttributeCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(2, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(2, diagnosticData.getAllOrphanRevocationReferences().size());
	}

}
