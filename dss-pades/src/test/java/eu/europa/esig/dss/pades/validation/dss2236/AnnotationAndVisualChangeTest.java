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
package eu.europa.esig.dss.pades.validation.dss2236;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AnnotationAndVisualChangeTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2236/annotation-and-visible-change.pdf"));
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		boolean firstSignatureFound = false;
		boolean secondSignatureFound = false;
		boolean thirdSignatureFound = false;
		
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.arePdfModificationsDetected());
			
			PDFRevisionWrapper pdfRevision = signature.getPDFRevision();
			assertNotNull(pdfRevision);
			assertTrue(pdfRevision.arePdfModificationsDetected());

			assertEquals(2, pdfRevision.getPdfAnnotationsOverlapConcernedPages().size());
			assertEquals(1, pdfRevision.getPdfAnnotationsOverlapConcernedPages().get(0).intValue());
			assertEquals(2, pdfRevision.getPdfAnnotationsOverlapConcernedPages().get(1).intValue());

			if (Utils.isCollectionNotEmpty(signature.getPdfExtensionChanges())) {

				assertTrue(signature.arePdfObjectModificationsDetected());

				assertTrue(Utils.isCollectionNotEmpty(signature.getPdfSignatureOrFormFillChanges()));
				assertTrue(Utils.isCollectionNotEmpty(signature.getPdfAnnotationChanges()));
				assertTrue(Utils.isCollectionNotEmpty(signature.getPdfUndefinedChanges()));

				firstSignatureFound = true;

			} else if (pdfRevision.arePdfObjectModificationsDetected()) {
				assertTrue(signature.arePdfObjectModificationsDetected());

				assertTrue(Utils.isCollectionNotEmpty(signature.getPdfSignatureOrFormFillChanges()));
				assertFalse(Utils.isCollectionNotEmpty(signature.getPdfAnnotationChanges()));
				assertFalse(Utils.isCollectionNotEmpty(signature.getPdfUndefinedChanges()));

				secondSignatureFound = true;

			} else {
				thirdSignatureFound = true;
			}
		}
		
		assertTrue(firstSignatureFound);
		assertTrue(secondSignatureFound);
		assertTrue(thirdSignatureFound);
	}

}
