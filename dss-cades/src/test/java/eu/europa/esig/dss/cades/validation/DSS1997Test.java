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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1997Test extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(DSS1997Test.class.getResourceAsStream("/validation/cades-dss1997.p7m"));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		assertEquals(3, diagnosticData.getTimestampList().size());

		boolean sigTstFound = false;
		boolean valDataTstFound = false;
		boolean arcTstFound = false;
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.SIGNATURE_TIMESTAMP == timestampWrapper.getType()) {
				assertTrue(timestampWrapper.isMessageImprintDataFound());
				assertTrue(timestampWrapper.isMessageImprintDataIntact());
				assertTrue(timestampWrapper.isSignatureIntact());
				assertTrue(timestampWrapper.isSignatureValid());
				sigTstFound = true;

			} else if (TimestampType.VALIDATION_DATA_TIMESTAMP == timestampWrapper.getType()) {
				assertTrue(timestampWrapper.isMessageImprintDataFound());
				assertTrue(timestampWrapper.isMessageImprintDataIntact());
				assertTrue(timestampWrapper.isSignatureIntact());
				assertTrue(timestampWrapper.isSignatureValid());
				valDataTstFound = true;

			} if (TimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getType()) {
				assertTrue(timestampWrapper.isMessageImprintDataFound());
				assertTrue(timestampWrapper.isMessageImprintDataIntact());
				assertTrue(timestampWrapper.isSignatureIntact());
				assertTrue(timestampWrapper.isSignatureValid());

				assertEquals(ArchiveTimestampType.CAdES_V3, timestampWrapper.getArchiveTimestampType());
				assertEquals(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX, timestampWrapper.getAtsHashIndexVersion());
				assertFalse(timestampWrapper.isAtsHashIndexValid());
				assertTrue(timestampWrapper.getAtsHashIndexValidationMessages().contains(
						"Some ats-hash-index attribute entries have not been found in unsignedAttrs."));
				arcTstFound = true;
			}
		}
		assertTrue(sigTstFound);
		assertTrue(valDataTstFound);
		assertTrue(arcTstFound);
	}
	
}
