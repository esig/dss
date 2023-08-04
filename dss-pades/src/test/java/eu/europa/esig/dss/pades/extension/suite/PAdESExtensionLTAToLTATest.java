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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PAdESExtensionLTAToLTATest extends AbstractPAdESTestExtension {

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_LTA;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.PAdES_BASELINE_LTA;
	}
	
	@Override
	protected void checkValidationContext(SignedDocumentValidator validator) {
		super.checkValidationContext(validator);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		AdvancedSignature advancedSignature = signatures.get(0);
		List<TimestampToken> allTimestamps = advancedSignature.getAllTimestamps();
		
		// second LTA
		if (allTimestamps.size() > 2) {
			PDFDocumentValidator pdfValidator = (PDFDocumentValidator) validator;
			// dss dict is not updated -> revision is not created by the validator
			assertEquals(1, pdfValidator.getDssDictionaries().size());
		}
	}

}
