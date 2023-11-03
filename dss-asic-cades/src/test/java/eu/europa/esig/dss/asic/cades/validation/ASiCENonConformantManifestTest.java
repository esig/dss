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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class ASiCENonConformantManifestTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/nonConformantManifest.asice");
	}
	
	@Override
	protected void checkValidationContext(SignedDocumentValidator validator) {
		super.checkValidationContext(validator);
		
		ASiCContainerWithCAdESValidator asicValidator = (ASiCContainerWithCAdESValidator) validator;
		
		List<DSSDocument> manifestDocuments = asicValidator.getManifestDocuments();
		List<ManifestFile> manifestFiles = asicValidator.getManifestFiles();
		assertEquals(manifestDocuments.size(), manifestFiles.size());
		assertEquals(1, manifestFiles.size());
		
		ManifestFile manifestFile = manifestFiles.get(0);
		assertNotNull(manifestFile.getFilename());
		assertNotNull(manifestFile.getSignatureFilename());
		assertTrue(Utils.isCollectionEmpty(manifestFile.getEntries()));
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionEmpty(validator.getOriginalDocuments(signatures.get(0))));
	}

}
