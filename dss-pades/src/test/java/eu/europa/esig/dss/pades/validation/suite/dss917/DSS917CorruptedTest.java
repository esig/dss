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
package eu.europa.esig.dss.pades.validation.suite.dss917;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS917CorruptedTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/hello_signed_INCSAVE_signed_EDITED.pdf"));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);

		List<SignatureWrapper> allSignatures = diagnosticData.getSignatures();
		assertEquals(2, allSignatures.size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		List<SignatureWrapper> allSignatures = diagnosticData.getSignatures();
		assertFalse(allSignatures.get(0).isBLevelTechnicallyValid());
		assertTrue(allSignatures.get(1).isBLevelTechnicallyValid());
	}

	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		int validByteRangeSigCounter = 0;
		int invalidByteRangeSigCounter = 0;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			XmlPDFRevision pdfRevision = signatureWrapper.getPDFRevision();
			assertNotNull(pdfRevision);
			assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getFields()));

			XmlPDFSignatureDictionary pdfSignatureDictionary = pdfRevision.getPDFSignatureDictionary();
			checkPdfSignatureDictionary(pdfSignatureDictionary);

			XmlByteRange signatureByteRange = pdfSignatureDictionary.getSignatureByteRange();
			if (signatureByteRange.isValid()) {
				++validByteRangeSigCounter;
			} else {
				++invalidByteRangeSigCounter;
			}

			assertFalse(signatureWrapper.arePdfModificationsDetected());
			assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges()));
		}
		assertEquals(1, validByteRangeSigCounter);
		assertEquals(1, invalidByteRangeSigCounter);
	}

	@Override
	protected void checkByteRange(XmlByteRange byteRange) {
		// skip
	}

}
