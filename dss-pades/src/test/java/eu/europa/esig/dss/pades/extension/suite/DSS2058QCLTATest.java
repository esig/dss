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
package eu.europa.esig.dss.pades.extension.suite;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Tag;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.extension.suite.dss2058.AbstractDSS2058;

@Tag("slow")
class DSS2058QCLTATest extends AbstractDSS2058 {

	@Override
	protected DSSDocument getDocumentToExtend() {
		return new InMemoryDocument(DSS2058QCLTATest.class.getResourceAsStream("/validation/dss-2058/dss-2058-QC-LTA-test.pdf"));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		// fails because one signature does not contain CMS timestamp
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		for (TimestampWrapper timestampToken : diagnosticData.getTimestampList()) {
			assertTrue(timestampToken.isMessageImprintDataFound());
			assertTrue(timestampToken.isMessageImprintDataIntact());
		}
	}

}
