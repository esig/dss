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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1972Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1959/pades-revoc-removed-from-dss-dict.pdf"));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		assertEquals(2, diagnosticData.getAllRevocationData().size());

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedRevocationWrapper> revocationData = signature.foundRevocations().getRelatedRevocationData();
		assertEquals(1, revocationData.size());

		String revocationId = revocationData.iterator().next().getId();
		
		int firstDssDictTimestampCounter = 0;
		int secondDssDictTimestampCounter = 0;
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
				List<RevocationWrapper> allTimestampedRevocations = timestampWrapper.getTimestampedRevocations();
				if (allTimestampedRevocations.size() == 1) {
					assertEquals(false, timestampWrapper.getTimestampedRevocations().stream().
							map(RevocationWrapper::getId).collect(Collectors.toList()).contains(revocationId));
					++firstDssDictTimestampCounter;
				} else if (allTimestampedRevocations.size() == 2) {
					assertEquals(true, timestampWrapper.getTimestampedRevocations().stream().
							map(RevocationWrapper::getId).collect(Collectors.toList()).contains(revocationId));
					++secondDssDictTimestampCounter;
				}
			}
		}
		assertEquals(1, firstDssDictTimestampCounter);
		assertEquals(2, secondDssDictTimestampCounter);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
	}

}
