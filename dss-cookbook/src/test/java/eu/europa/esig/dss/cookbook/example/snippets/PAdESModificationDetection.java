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
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESModificationDetection {

    public void demo() {

        // Initialize PDF document to be validated with skipped visual comparison
        DSSDocument signedDocument = new FileDocument("src/test/resources/snippets/25sigs.pdf");

        // Initialize validator
        PDFDocumentValidator validator = new PDFDocumentValidator(signedDocument);

        // Provide an instance of CertificateVerifier
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        // Initialize IPdfObjFactory
        // Note : example uses ServiceLoaderPdfObjFactory loading the available implementation in runtime.
        //        A custom implementation of IPdfObjFactory may be also provided, when applicable (e.g. PdfBoxNativeObjectFactory).
        IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

        // tag::visual-change-finder[]
        // import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;

        DefaultPdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();
        // The variable defines number of pages in a document to run the validation for
        // NOTE: setting '0' as MaximalPagesAmountForVisualComparison will skip the visual changes detection
        pdfDifferencesFinder.setMaximalPagesAmountForVisualComparison(1);
        // Provide a customized PdfDifferencesFinder within IPdfObjFactory
        pdfObjFactory.setPdfDifferencesFinder(pdfDifferencesFinder);
        // end::visual-change-finder[]

        // tag::object-modifications[]
        // import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;

        DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
        // The variable defines a limit of the nested objects to be verified (in case of too big PDFs)
        // NOTE: setting '0' as MaximumObjectVerificationDeepness will skip the object modification detection
        pdfObjectModificationsFinder.setMaximumObjectVerificationDeepness(100);
        // Sets whether an integer number shall be converted to a real for comparison against a real number
        // DEFAULT: TRUE (only absolute values of numbers are compared, but not type)
        pdfObjectModificationsFinder.setLaxNumericComparison(true);
        // Provide a customized PdfObjectModificationsFinder within IPdfObjFactory
        pdfObjFactory.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);
        // end::object-modifications[]

        // Set the factory to the DocumentValidator
        validator.setPdfObjFactory(pdfObjFactory);

        // Validate document
        Reports reports = validator.validateDocument();

    }

}
