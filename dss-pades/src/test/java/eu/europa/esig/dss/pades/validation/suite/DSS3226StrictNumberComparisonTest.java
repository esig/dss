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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS3226StrictNumberComparisonTest extends DSS3226Test {

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

        DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
        pdfObjectModificationsFinder.setLaxNumericComparison(false);
        pdfObjFactory.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);

        PDFDocumentValidator validator = (PDFDocumentValidator) super.getValidator(signedDocument);
        validator.setPdfObjFactory(pdfObjFactory);

        return validator;
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean invalidSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
            assertNotNull(pdfRevision);
            assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getSignatureFieldNames()));
            checkPdfSignatureDictionary(pdfRevision);

            assertFalse(signatureWrapper.arePdfModificationsDetected());
            if (Utils.isCollectionEmpty(signatureWrapper.getPdfUndefinedChanges())) {
                validSigFound = true;
            } else {
                invalidSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(invalidSigFound);
    }

}
