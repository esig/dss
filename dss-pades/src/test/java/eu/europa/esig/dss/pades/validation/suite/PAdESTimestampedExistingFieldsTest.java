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
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESTimestampedExistingFieldsTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/timestamped-fields.pdf"));
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertTrue(Utils.isCollectionEmpty(signatures));
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(0, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        super.checkPdfRevision(diagnosticData);

        boolean extendedTstFound = false;
        boolean lastTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertEquals(TimestampType.DOCUMENT_TIMESTAMP, timestampWrapper.getType());

            if (timestampWrapper.arePdfObjectModificationsDetected()) {
                PDFRevisionWrapper pdfRevision = timestampWrapper.getPDFRevision();
                assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getPdfExtensionChanges()));
                assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfSignatureOrFormFillChanges()));
                assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfAnnotationChanges()));
                assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfUndefinedChanges()));

                extendedTstFound = true;

            } else  {
                PDFRevisionWrapper pdfRevision = timestampWrapper.getPDFRevision();
                assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfExtensionChanges()));
                assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfSignatureOrFormFillChanges()));
                assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfAnnotationChanges()));
                assertFalse(Utils.isCollectionNotEmpty(pdfRevision.getPdfUndefinedChanges()));

                lastTstFound = true;
            }
        }
        assertTrue(extendedTstFound);
        assertTrue(lastTstFound);
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        assertNotNull(signatureValidationStatus);
        assertNotNull(signatureValidationStatus.getMainIndication());
        assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
    }

}
