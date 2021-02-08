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
package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASiCEWithXAdESCounterSignatureTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/container-with-counter-signature.asice");
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
			assertTrue(Utils.isCollectionNotEmpty(signatureScopes));
			
			boolean fullDocumentFound = false;
			for (XmlSignatureScope signatureScope : signatureScopes) {
				if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
					fullDocumentFound = true;
					if (signature.isCounterSignature()) {
						assertEquals("service-body.json", signatureScope.getName());
					} else {
						assertEquals("service-body-excl-debtor.json", signatureScope.getName());
					}
				}
			}
			assertTrue(fullDocumentFound);
		}
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		
		AdvancedSignature signature = signatures.iterator().next();
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatures.iterator().next());
		assertEquals(2, originalDocuments.size());

		List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
		assertEquals(1, counterSignatures.size());
		
		originalDocuments = validator.getOriginalDocuments(counterSignatures.iterator().next());
		assertEquals(6, originalDocuments.size());
	}

	@Override
	protected void checkStructureValidation(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertFalse(signatureWrapper.isStructuralValidationValid());
			assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getStructuralValidationMessages()));

			boolean notValidNameErrorFound = false;
			for (String error : signatureWrapper.getStructuralValidationMessages()) {
				if (error.contains("NCName")) {
					notValidNameErrorFound = true;
				}
			}
			assertTrue(notValidNameErrorFound);
		}
	}

}
