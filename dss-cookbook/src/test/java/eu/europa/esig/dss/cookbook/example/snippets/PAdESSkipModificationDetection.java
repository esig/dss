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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESSkipModificationDetection {

    public void demo() {

        // Initialize PDF document to be validated with skipped visual comparison
        DSSDocument signedDocument = new FileDocument("src/test/resources/snippets/25sigs.pdf");

        // tag::demo[]
        // import eu.europa.esig.dss.model.FileDocument;
        // import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
        // import eu.europa.esig.dss.pdf.IPdfObjFactory;
        // import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
        // import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
        // import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
        // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

        // Initialize validator
        PDFDocumentValidator validator = new PDFDocumentValidator(signedDocument);
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        // Create a IPdfObjFactory
        IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

        // Configure DefaultPdfDifferencesFinder responsible for visual document comparison
        DefaultPdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();
        // NOTE: To skip the visual comparison '0' value should be set
        pdfDifferencesFinder.setMaximalPagesAmountForVisualComparison(0);
        pdfObjFactory.setPdfDifferencesFinder(pdfDifferencesFinder);

        // Configure DefaultPdfObjectModificationsFinder responsible for object comparison between PDF revisions
        DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
        // NOTE: To skip the visual comparison '0' value should be set
        pdfObjectModificationsFinder.setMaximumObjectVerificationDeepness(0);
        pdfObjFactory.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);

        // Set the factory to the DocumentValidator
        validator.setPdfObjFactory(pdfObjFactory);
        // end::demo[]

        // Validate document
        Reports reports = validator.validateDocument();

    }
}
