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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCSWithCAdESCounterSignatureTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/containerWithCounterSig.asics");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		int counterSigCounter = 0;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.isCounterSignature()) {
				assertTrue(signatureWrapper.isBLevelTechnicallyValid());
				
				++counterSigCounter;
			}
		}
		assertEquals(1, counterSigCounter);
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);
		
		for (AdvancedSignature advancedSignature : validator.getSignatures()) {
			assertEquals(1, validator.getOriginalDocuments(advancedSignature).size());
		}
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertEquals(1, validator.getOriginalDocuments(signatureWrapper.getId()).size());
		}
	}

}
