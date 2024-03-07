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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExtensionBToTDocWithVRITest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());

        PAdESService padesService = new PAdESService(certificateVerifier);
        padesService.setTspSource(getGoodTsa());

        DSSDocument originalDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/test-with-vri.pdf"));

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        return padesService.extendDocument(originalDocument, signatureParameters);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        assertEquals(SignatureLevel.PAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signatureWrapper);

        List<TimestampWrapper> vriTimestamps = signatureWrapper.getVRITimestamps();
        assertEquals(0, vriTimestamps.size());

        List<TimestampWrapper> documentTimestamps = signatureWrapper.getDocumentTimestamps();
        assertEquals(1, documentTimestamps.size());

        List<TimestampWrapper> tLevelTimestamps = signatureWrapper.getTLevelTimestamps();
        assertEquals(1, tLevelTimestamps.size());

        List<TimestampWrapper> aLevelTimestamps = signatureWrapper.getALevelTimestamps();
        assertEquals(0, aLevelTimestamps.size());

        boolean docTstFound = false;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureValid());
            if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertEquals(2, timestampWrapper.getTimestampedSignedData().size());
                assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
                assertEquals(0, timestampWrapper.getTimestampedTimestamps().size());
                assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedCertificates()));
                assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedRevocations()));
                docTstFound = true;
            }
        }
        assertTrue(docTstFound);
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        PDFRevisionWrapper pdfRevision = signatureWrapper.getPDFRevision();
        assertNotNull(pdfRevision);
        assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getSignatureFieldNames()));
        checkPdfSignatureDictionary(pdfRevision);
    }

    @Override
    protected void checkVRIDictionaryCreationTime(DiagnosticData diagnosticData) {
        super.checkVRIDictionaryCreationTime(diagnosticData);

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signatureWrapper);
        assertNotNull(signatureWrapper.getVRIDictionaryCreationTime());
    }

}
