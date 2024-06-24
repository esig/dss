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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractOpenDocumentTestValidation extends AbstractASiCWithXAdESTestValidation {
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);

		assertTrue(areManifestAndMimetypeCovered(diagnosticData));
	}
	
	private boolean areManifestAndMimetypeCovered(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertTrue(Utils.isCollectionNotEmpty(signatureScopes));
		boolean isManifestCovered = false;
		boolean isMimetypeCovered = false;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (signatureScope.getName().contains("manifest.xml")) {
				isManifestCovered = true;
			} else if (signatureScope.getName().contains("mimetype")) {
				isMimetypeCovered = true;
			}
		}
		return isManifestCovered && isMimetypeCovered;
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		for (AdvancedSignature advancedSignature : validator.getSignatures()) {
			if (!advancedSignature.isCounterSignature()) {
				assertTrue(Utils.isCollectionNotEmpty(validator.getOriginalDocuments(advancedSignature)));
			}
		}
	}

}
