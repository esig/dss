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
package eu.europa.esig.dss.pades.validation.dss2236;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AnnotationAndVisualChangeTest extends AbstractPAdESTestValidation {

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
			
			XmlPDFRevision pdfRevision = signature.getPDFRevision();
			assertNotNull(pdfRevision);
			
			XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
			assertNotNull(modificationDetection);
			
			List<XmlModification> annotationOverlap = modificationDetection.getAnnotationOverlap();
			assertEquals(2, annotationOverlap.size());
			assertEquals(1, annotationOverlap.get(0).getPage().intValue());
			assertEquals(2, annotationOverlap.get(1).getPage().intValue());
			
			List<XmlModification> visualDifferences = modificationDetection.getVisualDifference();
			XmlObjectModifications objectModifications = modificationDetection.getObjectModifications();

			if (Utils.isCollectionNotEmpty(visualDifferences)) {
				assertEquals(1, visualDifferences.size());
				assertEquals(2, visualDifferences.get(0).getPage().intValue());

				assertNotNull(signature.arePdfObjectModificationsDetected());

				assertFalse(Utils.isCollectionNotEmpty(signature.getPdfExtensionChanges()));
				assertTrue(Utils.isCollectionNotEmpty(signature.getPdfSignatureOrFormFillChanges()));
				assertTrue(Utils.isCollectionNotEmpty(signature.getPdfAnnotationChanges()));
				assertTrue(Utils.isCollectionNotEmpty(signature.getPdfUndefinedChanges()));

				firstSignatureFound = true;

			} else if (objectModifications != null) {
				assertFalse(Utils.isCollectionNotEmpty(signature.getPdfExtensionChanges()));
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
