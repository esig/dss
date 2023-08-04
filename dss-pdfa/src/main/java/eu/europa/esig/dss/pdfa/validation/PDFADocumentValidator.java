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
package eu.europa.esig.dss.pdfa.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdfa.PDFAStructureValidator;
import eu.europa.esig.dss.pdfa.PDFAValidationResult;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DiagnosticDataBuilder;
import eu.europa.esig.dss.validation.ValidationContext;

import java.util.List;
import java.util.Objects;

/**
 * Validator used for PDF/A document validation
 *
 */
public class PDFADocumentValidator extends PDFDocumentValidator {

    /** Used to verify PDF against a PDF/A specification */
    private PDFAStructureValidator pdfaStructureValidator;

    /**
     * Empty constructor
     */
    protected PDFADocumentValidator() {
        // empty
    }

    /**
     * The default constructor for PDFADocumentValidator.
     *
     * @param document {@link DSSDocument}
     */
    public PDFADocumentValidator(DSSDocument document) {
        super(document);
    }

    private PDFAStructureValidator getPdfaStructureValidator() {
        if (pdfaStructureValidator == null) {
            pdfaStructureValidator = new PDFAStructureValidator();
        }
        return pdfaStructureValidator;
    }

    /**
     * Sets {@code PDFAStructureValidator} to verify a PDF/A document structure
     *
     * @param pdfaStructureValidator {@link PDFAStructureValidator}
     */
    public void setPdfaStructureValidator(PDFAStructureValidator pdfaStructureValidator) {
        Objects.requireNonNull(pdfaStructureValidator, "PDFAStructureValidator shall be defined!");
        this.pdfaStructureValidator = pdfaStructureValidator;
    }

    @Override
    protected DiagnosticDataBuilder createDiagnosticDataBuilder(final ValidationContext validationContext,
                                                                final List<AdvancedSignature> signatures) {
        PAdESWithPDFADiagnosticDataBuilder builder = (PAdESWithPDFADiagnosticDataBuilder) super.createDiagnosticDataBuilder(
                validationContext, signatures);
        builder.pdfaValidationResult(getPdfValidationResult());
        return builder;
    }

    @Override
    protected PAdESWithPDFADiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        return new PAdESWithPDFADiagnosticDataBuilder();
    }

    /**
     * This method returns a {@code document} validation result against PDF/A specification
     *
     * @return {@link PDFAValidationResult}
     */
    public PDFAValidationResult getPdfValidationResult() {
        return getPdfaStructureValidator().validate(document);
    }

}
