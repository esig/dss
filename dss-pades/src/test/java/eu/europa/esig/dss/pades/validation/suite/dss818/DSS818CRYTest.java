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
package eu.europa.esig.dss.pades.validation.suite.dss818;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DSS818CRYTest extends AbstractDSS818Test {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-818/Signature-P-DE_CRY-2 (HASH_FAILURE).pdf"));
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(2, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}

	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		assertEquals(SignatureLevel.PAdES_BES, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

}
