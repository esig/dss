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
package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Objects;

/**
 * Utility class to build a screenshot of PDF document
 *
 */
public class PdfBoxScreenshotBuilder {

    /** Document representing a PDF */
    private final DSSDocument pdfDocument;

    /** Password protection */
    private final char[] passwordProtection;

    /** Resources handler builder to be used on document processing (e.g. in memory vs temporary file) */
    private DSSResourcesHandlerBuilder dssResourcesHandlerBuilder;

    /** Memory usage settings to be used on a PDF reading */
    private PdfMemoryUsageSetting memoryUsageSetting;

    /**
     * Default constructor to generate a screenshot for a PDF document
     *
     * @param pdfDocument {@link DSSDocument}
     */
    protected PdfBoxScreenshotBuilder(final DSSDocument pdfDocument) {
        this(pdfDocument, null);
    }

    /**
     * Constructor to generate a screenshot for a password-protected PDF document
     *
     * @param pdfDocument {@link DSSDocument}
     * @param passwordProtection char array containing a passphrase for the PDF document
     */
    protected PdfBoxScreenshotBuilder(final DSSDocument pdfDocument, final char[] passwordProtection) {
        Objects.requireNonNull(pdfDocument, "PDF Document shall be defined!");
        this.pdfDocument = pdfDocument;
        this.passwordProtection = passwordProtection;
    }

    /**
     * Sets a resources handler builder for processing temporary documents (e.g. in memory vs temporary file)
     * Default : In-memory processing is used.
     *
     * @param dssResourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     * @return this {@link PdfBoxScreenshotBuilder}
     */
    public PdfBoxScreenshotBuilder setDSSResourcesHandlerBuilder(DSSResourcesHandlerBuilder dssResourcesHandlerBuilder) {
        this.dssResourcesHandlerBuilder = dssResourcesHandlerBuilder;
        return this;
    }

    /**
     * Gets PDF Memory Usage setting. Instantiates a default setting, if not defined.
     *
     * @return {@link PdfMemoryUsageSetting}
     */
    protected PdfMemoryUsageSetting getMemoryUsageSetting() {
        if (memoryUsageSetting == null) {
            memoryUsageSetting = PAdESUtils.DEFAULT_PDF_MEMORY_USAGE_SETTING;
        }
        return memoryUsageSetting;
    }

    /**
     * Sets PDF memory usage settings on PDF document reading.
     * Default : PDF document is fully loaded in memory.
     *
     * @param memoryUsageSetting {@link PdfMemoryUsageSetting}
     * @return this {@link PdfBoxScreenshotBuilder}
     */
    public PdfBoxScreenshotBuilder setMemoryUsageSetting(PdfMemoryUsageSetting memoryUsageSetting) {
        this.memoryUsageSetting = memoryUsageSetting;
        return this;
    }

    /**
     * Creates a new {@code PdfBoxScreenshotBuilder} for the given {@code DSSDocument}
     *
     * @param pdfDocument {@link DSSDocument} to build a screenshot for
     * @return {@link PdfBoxScreenshotBuilder}
     */
    public static PdfBoxScreenshotBuilder fromDocument(DSSDocument pdfDocument) {
        return new PdfBoxScreenshotBuilder(pdfDocument);
    }

    /**
     * Creates a new {@code PdfBoxScreenshotBuilder} for the password-protected {@code DSSDocument}
     *
     * @param pdfDocument {@link DSSDocument} to build a screenshot for
     * @param passwordProtection char array containing a passphrase for the PDF document
     * @return {@link PdfBoxScreenshotBuilder}
     */
    public static PdfBoxScreenshotBuilder fromDocument(DSSDocument pdfDocument, char[] passwordProtection) {
        return new PdfBoxScreenshotBuilder(pdfDocument, passwordProtection);
    }

    /**
     * Generates a screenshot image of the specified page for the given PDF document
     *
     * @param page a page number to generate screenshot for (page order starts from 1)
     * @return {@link DSSDocument} PNG screenshot
     */
    public DSSDocument generateScreenshot(int page) {
        BufferedImage bufferedImage = generateBufferedImageScreenshot(page);
        return ImageUtils.toDSSDocument(bufferedImage, initDssResourcesHandler());
    }

    /**
     * Generates a screenshot image of the specified page for the given PDF document using
     * the provided {@code dssResourcesHandler}.
     * NOTE: This is a temporary method to ensure a smooth migration. Please do not use it.
     *
     * @param page a page number to generate screenshot for (page order starts from 1)
     * @param dssResourcesHandler {@link DSSResourcesHandler}
     * @return {@link DSSDocument} PNG screenshot
     * @deprecated since DSS 6.2. This is a temporary method to ensure smooth migration.
     */
    @Deprecated
    public DSSDocument generateScreenshot(int page, DSSResourcesHandler dssResourcesHandler) {
        // to be removed
        BufferedImage bufferedImage = generateBufferedImageScreenshot(page);
        return ImageUtils.toDSSDocument(bufferedImage, dssResourcesHandler);
    }

    /**
     * The method generates a BufferedImage for the specified page of the document
     *
     * @param page a page number to generate screenshot for (page order starts from 1)
     * @return {@link BufferedImage}
     */
    public BufferedImage generateBufferedImageScreenshot(int page) {
        try (PdfBoxDocumentReader reader = new PdfBoxDocumentReader(pdfDocument,
                passwordProtection != null ? new String(passwordProtection) : null, getMemoryUsageSetting())) {
            return reader.generateImageScreenshot(page);
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to generate a screenshot for the document with name '%s' "
                    + "for the page number '%s'. Reason : %s", pdfDocument.getName(), page, e.getMessage()), e);
        }
    }

    /**
     * Creates a new instance of {@code DSSResourcesHandler}.
     * Instantiates default {@code DSSResourcesHandlerBuilder} if not defined.
     *
     * @return {@link DSSResourcesHandler}
     */
    protected DSSResourcesHandler initDssResourcesHandler() {
        if (dssResourcesHandlerBuilder == null) {
            dssResourcesHandlerBuilder = PAdESUtils.DEFAULT_RESOURCES_HANDLER_BUILDER;
        }
        return dssResourcesHandlerBuilder.createResourcesHandler();
    }

}
