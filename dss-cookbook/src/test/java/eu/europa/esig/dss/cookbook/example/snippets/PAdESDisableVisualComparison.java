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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.modifications.PdfModificationDetectionUtils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESDisableVisualComparison {

    public void demo() {

        // Initialize PDF document to be validated with skipped visual comparison
        DSSDocument signedDocument = new FileDocument("src/test/resources/snippets/25sigs.pdf");

        // Initialize validator
        PDFDocumentValidator validator = new PDFDocumentValidator(signedDocument);

        // Provide an instance of CertificateVerifier
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        // tag::visual-change-finder[]
        DefaultPdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();
        // NOTE: setting '0' as MaximalPagesAmountForVisualComparison will skip the visual changes detection
        pdfDifferencesFinder.setMaximalPagesAmountForVisualComparison(0);
        // Provide a customized PdfDifferencesFinder within PdfModificationDetectionUtils
        PdfModificationDetectionUtils.getInstance().setPdfDifferencesFinder(pdfDifferencesFinder);
        // end::visual-change-finder[]

        // tag::object-modifications[]
        DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
        // The variable defines a limit of the nested objects to be verified (in case of too big PDFs)
        pdfObjectModificationsFinder.setMaximumObjectVerificationDeepness(100);
        // Provide a customized PdfObjectModificationsFinder within PdfModificationDetectionUtils
        PdfModificationDetectionUtils.getInstance().setPdfObjectModificationsFinder(pdfObjectModificationsFinder);
        // end::object-modifications[]

        // Validate document
        Reports reports = validator.validateDocument();

    }

}
