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

/**
 * Validator used for PDF/A document validation
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class PDFADocumentValidator extends PDFDocumentValidator {

    /**
     * Empty constructor
     */
    protected PDFADocumentValidator() {
        super(new PDFADocumentAnalyzer());
    }

    /**
     * The default constructor for PDFADocumentValidator.
     *
     * @param document {@link DSSDocument}
     */
    public PDFADocumentValidator(DSSDocument document) {
        super(new PDFADocumentAnalyzer(document));
    }

    @Override
    public PDFADocumentAnalyzer getDocumentAnalyzer() {
        return (PDFADocumentAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * Sets {@code PDFAStructureValidator} to verify a PDF/A document structure
     *
     * @param pdfaStructureValidator {@link PDFAStructureValidator}
     */
    public void setPdfaStructureValidator(PDFAStructureValidator pdfaStructureValidator) {
        getDocumentAnalyzer().setPdfaStructureValidator(pdfaStructureValidator);
    }

    /**
     * This method returns a {@code document} validation result against PDF/A specification
     *
     * @return {@link PDFAValidationResult}
     */
    public PDFAValidationResult getPdfaValidationResult() {
        return getDocumentAnalyzer().getPdfaValidationResult();
    }

    @Override
    protected PAdESWithPDFADiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        final PAdESWithPDFADiagnosticDataBuilder padesWithPDFADiagnosticDataBuilder = new PAdESWithPDFADiagnosticDataBuilder();
        padesWithPDFADiagnosticDataBuilder.pdfaValidationResult(getPdfaValidationResult());
        return padesWithPDFADiagnosticDataBuilder;
    }

}