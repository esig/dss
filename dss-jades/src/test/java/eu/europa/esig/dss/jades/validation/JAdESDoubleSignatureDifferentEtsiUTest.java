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
package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class JAdESDoubleSignatureDifferentEtsiUTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/jades-double-sig-different-etsiU.json");
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);
		assertEquals(2, diagnosticData.getSignatures().size());
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);

		boolean ltSignatureFound = false;
		boolean ltaSignatureFound = false;
		for (String signatureId : diagnosticData.getSignatureIdList()) {
			if (SignatureLevel.JAdES_BASELINE_LT.equals(diagnosticData.getSignatureFormat(signatureId))) {
				ltSignatureFound = true;
			} else if (SignatureLevel.JAdES_BASELINE_LTA.equals(diagnosticData.getSignatureFormat(signatureId))) {
				ltaSignatureFound = true;
			}
		}
		assertTrue(ltSignatureFound);
		assertTrue(ltaSignatureFound);
	}

}
