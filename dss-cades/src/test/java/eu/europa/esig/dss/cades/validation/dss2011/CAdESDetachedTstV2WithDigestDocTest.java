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
package eu.europa.esig.dss.cades.validation.dss2011;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Tag;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESDetachedTstV2WithDigestDocTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(CAdESDetachedTstV2WithDigestDocTest.class.getResourceAsStream("/validation/dss-2011/cades-tstv2-detached.p7s"));
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		DigestDocument digestDocument = new DigestDocument();
		digestDocument.addDigest(DigestAlgorithm.SHA256, new InMemoryDocument("aaa".getBytes(), "data.txt").getDigestValue(DigestAlgorithm.SHA256));
		return Collections.singletonList(digestDocument);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		// not able to compute message imprint for ATSTv2 without original binaries
				int v2ArchiveTsts = 0;
				for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
					if (ArchiveTimestampType.CAdES_V2.equals(timestamp.getArchiveTimestampType())) {
						assertFalse(timestamp.isMessageImprintDataFound());
						assertFalse(timestamp.isMessageImprintDataIntact());
						++v2ArchiveTsts;
					}
				}
				assertEquals(1, v2ArchiveTsts);
	}

}
