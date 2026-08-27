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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS3946ModifiedSigAnnotationTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-alter-signature.pdf"));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        boolean firstSignatureFound = false;
        boolean secondSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
            assertNotNull(pdfRevision);

            if ("AliceSig".equals(signatureWrapper.getFirstFieldName())) {
                assertTrue(pdfRevision.isPdfSignatureDictionaryConsistent());
                checkByteRange(pdfRevision);

                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfExtensionChanges()));
                // we expect to find 66 0 R added in /Annots and /Fields arrays
                assertEquals(2, Utils.collectionSize(signatureWrapper.getPdfSignatureOrFormFillChanges()));
                assertEquals(2, signatureWrapper.getPdfSignatureOrFormFillChanges().stream()
                        .filter(m -> m.getValue().contains("66 0 R")).count());
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfAnnotationChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges()));

                firstSignatureFound = true;

            } else if ("BobSig".equals(signatureWrapper.getFirstFieldName())) {
                assertFalse(pdfRevision.isPdfSignatureDictionaryConsistent());
                checkByteRange(pdfRevision);

                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfExtensionChanges()));
                // avoid /Rect to be processed twice
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfSignatureOrFormFillChanges()));
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getPdfAnnotationChanges()));
                assertEquals(3, Utils.collectionSize(signatureWrapper.getPdfUndefinedChanges()));
                assertEquals(1, signatureWrapper.getPdfUndefinedChanges().stream()
                        .filter(m -> m.getValue().contains("/Rect")).count());

                secondSignatureFound = true;
            }
        }
        assertTrue(firstSignatureFound);
        assertTrue(secondSignatureFound);
    }

}
