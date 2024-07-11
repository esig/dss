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
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PdBoxAnnotationAndVisualChangeTest extends AnnotationAndVisualChangeTest {

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        super.checkPdfRevision(diagnosticData);

        boolean firstSignatureFound = false;
        boolean secondSignatureFound = false;
        boolean thirdSignatureFound = false;

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            assertTrue(signature.arePdfModificationsDetected());

            PDFRevisionWrapper pdfRevision = signature.getPDFRevision();
            assertNotNull(pdfRevision);
            assertTrue(pdfRevision.arePdfModificationsDetected());

            if (Utils.isCollectionNotEmpty(pdfRevision.getPdfVisualDifferenceConcernedPages())) {
                assertEquals(1, pdfRevision.getPdfVisualDifferenceConcernedPages().size());
                assertEquals(2, pdfRevision.getPdfVisualDifferenceConcernedPages().get(0).intValue());

                firstSignatureFound = true;

            } else if (pdfRevision.arePdfObjectModificationsDetected()) {
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
