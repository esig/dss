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

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2821ExtensionToTLevelTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-2821.pdf"));

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert());

        PAdESService service = new PAdESService(certificateVerifier);
        service.setTspSource(getSelfSignedTsa());

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        return service.extendDocument(dssDocument, parameters);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.PAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.arePdfObjectModificationsDetected());
        assertTrue(Utils.isCollectionNotEmpty(signature.getPdfExtensionChanges()));
        // skip signature.getPdfSignatureOrFormFillChanges() as PdfBox/OpenPdf have different processing
        assertFalse(Utils.isCollectionNotEmpty(signature.getPdfAnnotationChanges()));
        assertFalse(Utils.isCollectionNotEmpty(signature.getPdfUndefinedChanges()));

        TimestampWrapper detachedTst = diagnosticData.getTimestampList().get(0);
        assertFalse(Utils.isCollectionNotEmpty(detachedTst.getTimestampedSignatures()));

        assertTrue(detachedTst.arePdfObjectModificationsDetected());
        assertTrue(Utils.isCollectionNotEmpty(detachedTst.getPdfExtensionChanges()));
        assertTrue(Utils.isCollectionNotEmpty(detachedTst.getPdfSignatureOrFormFillChanges()));
        assertTrue(Utils.isCollectionNotEmpty(detachedTst.getPdfAnnotationChanges()));
        assertTrue(Utils.isCollectionNotEmpty(detachedTst.getPdfUndefinedChanges()));

        TimestampWrapper docTst = diagnosticData.getTimestampList().get(1);
        assertTrue(Utils.isCollectionNotEmpty(docTst.getTimestampedSignatures()));
        assertFalse(docTst.arePdfObjectModificationsDetected());
    }

}
