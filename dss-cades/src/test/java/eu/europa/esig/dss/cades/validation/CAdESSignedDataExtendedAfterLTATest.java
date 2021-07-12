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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESSignedDataExtendedAfterLTATest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/cades_signeddata_extended_after_lta.p7m");
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<TimestampWrapper> allTimestamps = signatureById.getTimestampList();
		
		assertEquals(0, allTimestamps.get(0).getTimestampedRevocations().size());
		assertEquals(2, allTimestamps.get(1).getTimestampedRevocations().size());
		assertEquals(3, allTimestamps.get(2).getTimestampedRevocations().size());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkTimestampedProperties(Collection<TimestampWrapper> allTimestamps, TimestampWrapper timestampWrapper,
											  Collection<SignatureWrapper> allSignatures, SignatureWrapper signatureWrapper) {
		// skip (wrong hash of ats-hash-index-v3)
	}

}
