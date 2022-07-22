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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModificationsFinder;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandlerBuilder;

/**
 * An abstract implementation of IPdfObjFactory allowing to set the configuration options
 *
 */
public abstract class AbstractPdfObjFactory implements IPdfObjFactory {

    /**
     * This object is used to create data container objects such as an OutputStream or a DSSDocument
     */
    private DSSResourcesHandlerBuilder resourcesHandlerBuilder;

    /**
     * Used to find differences occurred between PDF revisions (e.g. visible changes).
     */
    private PdfDifferencesFinder pdfDifferencesFinder;

    /**
     * Used to find differences within internal PDF objects occurred between PDF revisions .
     */
    private PdfObjectModificationsFinder pdfObjectModificationsFinder;

    @Override
    public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        this.resourcesHandlerBuilder = resourcesHandlerBuilder;
    }

    @Override
    public void setPdfDifferencesFinder(PdfDifferencesFinder pdfDifferencesFinder) {
        this.pdfDifferencesFinder = pdfDifferencesFinder;
    }

    @Override
    public void setPdfObjectModificationsFinder(PdfObjectModificationsFinder pdfObjectModificationsFinder) {
        this.pdfObjectModificationsFinder = pdfObjectModificationsFinder;
    }

    /**
     * This method is used to provide configuration to the given {@code pdfSignatureService}
     * (e.g. set the resources handler builder).
     *
     * @param pdfSignatureService {@link PDFSignatureService} to configure
     * @return {@link PDFSignatureService} configured
     */
    protected PDFSignatureService configure(PDFSignatureService pdfSignatureService) {
        if (resourcesHandlerBuilder != null) {
            pdfSignatureService.setResourcesHandlerBuilder(resourcesHandlerBuilder);
        }
        if (pdfDifferencesFinder != null) {
            pdfSignatureService.setPdfDifferencesFinder(pdfDifferencesFinder);
        }
        if (pdfObjectModificationsFinder != null) {
            pdfSignatureService.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);
        }
        return pdfSignatureService;
    }

}
