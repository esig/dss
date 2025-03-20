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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzer;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESExtensionLTWithVRIToLTATest extends PAdESExtensionLTToLTATest {

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        PAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setIncludeVRIDictionary(true);
        return signatureParameters;
    }

    @Override
    protected PAdESSignatureParameters getExtensionParameters() {
        PAdESSignatureParameters extensionParameters = super.getExtensionParameters();
        extensionParameters.setIncludeVRIDictionary(false);
        return extensionParameters;
    }

    @Override
    protected void onDocumentSigned(DSSDocument signedDocument) {
        super.onDocumentSigned(signedDocument);

        PDFDocumentAnalyzer documentValidator = new PDFDocumentAnalyzer(signedDocument);

        List<AdvancedSignature> signatures = documentValidator.getSignatures();
        assertEquals(1, signatures.size());

        PAdESSignature padesSignature = (PAdESSignature) signatures.get(0);

        PdfDssDict dssDictionary = padesSignature.getDssDictionary();
        assertNotNull(dssDictionary);

        assertTrue(Utils.isMapNotEmpty(dssDictionary.getCERTs()));
        assertTrue(Utils.isMapNotEmpty(dssDictionary.getCRLs()));
        assertTrue(Utils.isMapNotEmpty(dssDictionary.getOCSPs()));
        assertTrue(Utils.isCollectionNotEmpty(dssDictionary.getVRIs()));

        assertEquals(1, dssDictionary.getVRIs().size());
        PdfVriDict pdfVriDict = dssDictionary.getVRIs().get(0);
        assertTrue(Utils.isMapNotEmpty(pdfVriDict.getCERTs()));
        assertTrue(Utils.isMapNotEmpty(pdfVriDict.getCRLs()));
        assertTrue(Utils.isMapNotEmpty(pdfVriDict.getOCSPs()));
    }

    @Override
    protected void onDocumentExtended(DSSDocument extendedDocument) {
        super.onDocumentExtended(extendedDocument);

        PDFDocumentAnalyzer documentValidator = new PDFDocumentAnalyzer(extendedDocument);

        List<AdvancedSignature> signatures = documentValidator.getSignatures();
        assertEquals(1, signatures.size());

        PAdESSignature padesSignature = (PAdESSignature) signatures.get(0);

        PdfDssDict dssDictionary = padesSignature.getDssDictionary();
        assertNotNull(dssDictionary);

        assertTrue(Utils.isMapNotEmpty(dssDictionary.getCERTs()));
        assertTrue(Utils.isMapNotEmpty(dssDictionary.getCRLs()));
        assertTrue(Utils.isMapNotEmpty(dssDictionary.getOCSPs()));
        assertFalse(Utils.isCollectionNotEmpty(dssDictionary.getVRIs()));
    }

}
