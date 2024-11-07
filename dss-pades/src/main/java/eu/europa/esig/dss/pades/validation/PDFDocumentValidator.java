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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

/**
 * Validation of PDF document.
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class PDFDocumentValidator extends SignedDocumentValidator {

    /**
     * Empty constructor
     */
    protected PDFDocumentValidator() {
        super(new PDFDocumentAnalyzer());
    }

    /**
     * Constructor with a {@code PDFDocumentAnalyzer}
     *
     * @param pdfDocumentAnalyzer {@link PDFDocumentAnalyzer}
     */
    protected PDFDocumentValidator(PDFDocumentAnalyzer pdfDocumentAnalyzer) {
        super(pdfDocumentAnalyzer);
    }

    /**
     * The default constructor for PDFDocumentValidator.
     *
     * @param document {@link DSSDocument}
     */
    public PDFDocumentValidator(final DSSDocument document) {
        super(new PDFDocumentAnalyzer(document));
    }

    @Override
    public PDFDocumentAnalyzer getDocumentAnalyzer() {
        return (PDFDocumentAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * Set the IPdfObjFactory. Allow to set the used implementation. Cannot be null.
     *
     * @param pdfObjFactory the implementation to be used.
     */
    public void setPdfObjFactory(IPdfObjFactory pdfObjFactory) {
        getDocumentAnalyzer().setPdfObjFactory(pdfObjFactory);
    }

    /**
     * Specify the used password for the encrypted document
     *
     * @param passwordProtection the used password
     */
    public void setPasswordProtection(char[] passwordProtection) {
        getDocumentAnalyzer().setPasswordProtection(passwordProtection);
    }

    @Override
    protected PAdESDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        return new PAdESDiagnosticDataBuilder();
    }

    /**
     * Returns a list of found DSS Dictionaries across different revisions
     *
     * @return list of {@link PdfDssDict}s
     */
    public List<PdfDssDict> getDssDictionaries() {
        return getDocumentAnalyzer().getDssDictionaries();
    }

    /**
     * Gets the list of PDF document revisions
     *
     * @return a list of {@link PdfRevision}s
     */
    public List<PdfRevision> getRevisions() {
        return getDocumentAnalyzer().getRevisions();
    }

}