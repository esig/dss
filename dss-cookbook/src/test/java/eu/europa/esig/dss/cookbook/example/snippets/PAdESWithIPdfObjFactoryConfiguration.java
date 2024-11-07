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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.alerts.ProtectedDocumentExceptionOnStatusAlert;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.PdfPermissionsChecker;
import eu.europa.esig.dss.pdf.PdfSignatureFieldPositionChecker;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESWithIPdfObjFactoryConfiguration {

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

        // tag::pdf-permission-checker[]
        // import eu.europa.esig.dss.pdf.PdfPermissionsChecker;
        // import eu.europa.esig.dss.pades.alerts.ProtectedDocumentExceptionOnStatusAlert;

        // Instantiate PdfPermissionsChecker object
        PdfPermissionsChecker pdfPermissionsChecker = new PdfPermissionsChecker();

        // Set the behavior using an Alert
        // Default : ProtectedDocumentExceptionOnStatusAlert (throws a ProtectedDocumentException if a document restricts signature creation)
        pdfPermissionsChecker.setAlertOnForbiddenSignatureCreation(new ProtectedDocumentExceptionOnStatusAlert());

        // Provide PdfPermissionsChecker to IPdfObjFactory instance defined in a PAdESService
        pdfObjFactory.setPdfPermissionsChecker(pdfPermissionsChecker);
        // end::pdf-permission-checker[]

        // tag::pdf-signature-field-position-checker[]
        // import eu.europa.esig.dss.pdf.PdfSignatureFieldPositionChecker;
        // import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;

        // Instantiate PdfSignatureFieldPositionChecker object
        PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker = new PdfSignatureFieldPositionChecker();

        // This method defines a behavior in case a new signature field overlaps an existing annotations within PDF document
        // Default : ExceptionOnStatusAlert (throws a AlertException if the new signature field overlaps with existing annotations)
        pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOverlap(new ExceptionOnStatusAlert());

        // This method defines a behavior in case a new signature field lies outside (full or partially) of the defined page within the PDF document
        // Default : ExceptionOnStatusAlert (throws a AlertException if the new signature field lies outside PDF page)
        pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(new ExceptionOnStatusAlert());

        // Provide PdfSignatureFieldPositionChecker to IPdfObjFactory instance defined in a PAdESService
        pdfObjFactory.setPdfSignatureFieldPositionChecker(pdfSignatureFieldPositionChecker);
        // end::pdf-signature-field-position-checker[]

        // tag::pdf-memory-usage-setting[]
        // import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;

        // Creates a configuration of memory usage on a PDF document reading,
        // with the PDF document being fully load into the memory before parsing.
        // NOTE: The setting is used by default.
        PdfMemoryUsageSetting pdfFullInMemoryUsageSetting = PdfMemoryUsageSetting.memoryFull();

        // Loads the parts of the PDF document into memory during its parsing
        PdfMemoryUsageSetting pdfMemoryBufferedUsageSetting = PdfMemoryUsageSetting.memoryBuffered();

        // Loads the parts of the PDF document into memory during its parsing.
        // Allows definition of maximum number of bytes to be loaded into the memory.
        // For example 2^20 bytes (1 Megabyte)
        PdfMemoryUsageSetting pdfMemoryBufferedUsageWithLimitSetting = PdfMemoryUsageSetting.memoryBuffered(2^20);

        // Loads the parts of the PDF document in the mixed mode, with bytes
        // being allocated into the memory before the defined limit.
        // All bytes after will be stored in a temporary file.
        // For example 2^20 bytes (1 Megabyte).
        PdfMemoryUsageSetting pdfMixedUsageSetting = PdfMemoryUsageSetting.mixed(2^20);

        // Loads the parts of the PDF document in the mixed mode, with bytes
        // being allocated into the memory before the defined limit.
        // All bytes after will be stored in a temporary file before the defined limit.
        // For example 2^20 bytes (1 Megabyte) for a memory storage limit,
        // and 2^30 (1 Gigabyte) for a temporary file size limit.
        PdfMemoryUsageSetting pdfMixedUsageWithTempFileLimitSetting = PdfMemoryUsageSetting.mixed(2^20, 2^30);

        // Loads the parts of a PDF document into a temporary file in filesystem during parsing.
        PdfMemoryUsageSetting pdfFileOnlyUsageSetting = PdfMemoryUsageSetting.fileOnly();

        // Loads the parts of a PDF document into a temporary file in filesystem during parsing,
        // before the specified limit.
        // For example 2^30 (1 Gigabyte) for a temporary file size limit.
        PdfMemoryUsageSetting pdfFileOnlyUsageWithLimitSetting = PdfMemoryUsageSetting.fileOnly(2^30);

        // Provide chosen PdfMemoryUsageSetting to IPdfObjFactory instance
        // defined in a PAdESService or PDFDocumentValidator
        pdfObjFactory.setPdfMemoryUsageSetting(pdfFullInMemoryUsageSetting);

        // end::pdf-memory-usage-setting[]

        // Set the factory to the DocumentValidator
        validator.setPdfObjFactory(pdfObjFactory);

        // Validate document
        Reports reports = validator.validateDocument();

    }

}
