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
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2451Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-byterange-overlap.pdf"));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean validSigFound = false;
        boolean failedSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isBLevelTechnicallyValid()) {
                validSigFound = true;
            } else {
                failedSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(failedSigFound);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        boolean validSigFound = false;
        boolean failedSigFound = false;
        for (String signatureId : simpleReport.getSignatureIdList()) {
            if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(signatureId))) {
                assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(signatureId));
                failedSigFound = true;
            } else {
                validSigFound = true;
            }
        }
        assertTrue(validSigFound);
        assertTrue(failedSigFound);
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        int validByteRangeSigCounter = 0;
        int invalidByteRangeSigCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
            assertNotNull(pdfRevision);
            assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getSignatureFieldNames()));
            checkPdfSignatureDictionary(pdfRevision);

            if (pdfRevision.isSignatureByteRangeValid()) {
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
    protected void checkByteRange(PDFRevisionWrapper pdfRevision) {
        // skip
    }

}
