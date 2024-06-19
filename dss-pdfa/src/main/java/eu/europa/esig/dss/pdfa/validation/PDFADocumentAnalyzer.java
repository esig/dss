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
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzer;
import eu.europa.esig.dss.pdfa.PDFAStructureValidator;
import eu.europa.esig.dss.pdfa.PDFAValidationResult;

import java.util.Objects;

/**
 * Validator used for PDF/A document validation
 *
 */
public class PDFADocumentAnalyzer extends PDFDocumentAnalyzer {

    /** Used to verify PDF against a PDF/A specification */
    private PDFAStructureValidator pdfaStructureValidator;

    /**
     * Empty constructor
     */
    protected PDFADocumentAnalyzer() {
        // empty
    }

    /**
     * The default constructor for PDFADocumentValidator.
     *
     * @param document {@link DSSDocument}
     */
    public PDFADocumentAnalyzer(DSSDocument document) {
        super(document);
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

    /**
     * This method returns a {@code document} validation result against PDF/A specification
     *
     * @return {@link PDFAValidationResult}
     */
    public PDFAValidationResult getPdfaValidationResult() {
        return getPdfaStructureValidator().validate(document);
    }

    private PDFAStructureValidator getPdfaStructureValidator() {
        if (pdfaStructureValidator == null) {
            pdfaStructureValidator = new PDFAStructureValidator();
        }
        return pdfaStructureValidator;
    }

}
