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
package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.PdfAnnotation;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Default implementation used to find differences in pages between two PDF revisions.
 *
 */
public class DefaultPdfDifferencesFinder implements PdfDifferencesFinder {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultPdfDifferencesFinder.class);

    /**
     * This variable sets the maximal amount of pages in a PDF to execute visual
     * screenshot comparison for Example: for value 10, the visual comparison will
     * be executed for a PDF containing 10 and fewer pages
     *
     * Default : 10 pages
     */
    private int maximalPagesAmountForVisualComparison = 10;

    /**
     * Sets a maximal pages amount in a PDF to process a visual screenshot
     * comparison Example: for value 10, the visual comparison will be executed for
     * a PDF containing 10 and fewer pages
     *
     * NOTE: In order to disable visual comparison check set the pages amount to 0
     * (zero)
     *
     * Default : 10 pages
     *
     * @param pagesAmount the amount of the pages to execute visual comparison for
     */
    public void setMaximalPagesAmountForVisualComparison(int pagesAmount) {
        this.maximalPagesAmountForVisualComparison = pagesAmount;
    }

    /**
     * Default constructor instantiating object with default configuration
     */
    public DefaultPdfDifferencesFinder() {
        // empty
    }

    @Override
    public List<PdfModification> getAnnotationOverlaps(final PdfDocumentReader reader) {
        List<PdfModification> annotationOverlaps = new ArrayList<>();

        for (int pageNumber = 1; pageNumber <= reader.getNumberOfPages(); pageNumber++) {
            List<PdfAnnotation> pdfAnnotations = getPdfAnnotations(reader, pageNumber);
            Iterator<PdfAnnotation> iterator = pdfAnnotations.iterator();
            while (iterator.hasNext()) {
                PdfAnnotation annotation = iterator.next();
                iterator.remove(); // remove the annotations from the comparison list
                if (isAnnotationBoxOverlapping(annotation.getAnnotationBox(), pdfAnnotations)) {
                    annotationOverlaps.add(new CommonPdfModification(pageNumber));
                    break;
                }
            }
        }

        return annotationOverlaps;
    }

    private List<PdfAnnotation> getPdfAnnotations(PdfDocumentReader reader, int pageNumber) {
        try {
            return reader.getPdfAnnotations(pageNumber);
        } catch (IOException e) {
            LOG.warn("Unable to extract annotations from a PDF document for a page number : {}. Reason : {}",
                    pageNumber, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    @Override
    public boolean isAnnotationBoxOverlapping(AnnotationBox annotationBox, List<PdfAnnotation> pdfAnnotations) {
        if (annotationBox.getWidth() == 0 || annotationBox.getHeight() == 0) {
            // invisible field
            return false;
        }
        for (PdfAnnotation pdfAnnotation : pdfAnnotations) {
            if (annotationBox.isOverlap(pdfAnnotation)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<PdfModification> getPagesDifferences(final PdfDocumentReader signedRevisionReader,
                                                     final PdfDocumentReader finalRevisionReader) {
        int signedPages = signedRevisionReader.getNumberOfPages();
        int finalPages = finalRevisionReader.getNumberOfPages();

        int maxNumberOfPages = Math.max(signedPages, finalPages);
        int minNumberOfPages = Math.min(signedPages, finalPages);

        List<PdfModification> missingPages = new ArrayList<>();
        for (int ii = maxNumberOfPages; ii > minNumberOfPages; ii--) {
            missingPages.add(new CommonPdfModification(ii));
        }

        if (Utils.isCollectionNotEmpty(missingPages)) {
            LOG.warn("The provided PDF file contains {} additional pages against the signed revision!",
                    maxNumberOfPages - minNumberOfPages);
        }

        return missingPages;
    }

    @Override
    public List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
                                                      final PdfDocumentReader finalRevisionReader) {
        int pagesAmount = finalRevisionReader.getNumberOfPages();
        if (maximalPagesAmountForVisualComparison < pagesAmount) {
            LOG.debug("The provided document contains {} pages, while the limit for a visual comparison is set to {}. " +
                    "Visual differences comparison is skipped.", pagesAmount, maximalPagesAmountForVisualComparison);
            return Collections.emptyList();
        }

        final List<PdfModification> visualDifferences = new ArrayList<>();
        for (int pageNumber = 1; pageNumber <= signedRevisionReader.getNumberOfPages()
                && pageNumber <= finalRevisionReader.getNumberOfPages(); pageNumber++) {
            try {
                BufferedImage signedScreenshot = signedRevisionReader.generateImageScreenshot(pageNumber);

                List<PdfAnnotation> signedAnnotations = signedRevisionReader.getPdfAnnotations(pageNumber);
                List<PdfAnnotation> finalAnnotations = finalRevisionReader.getPdfAnnotations(pageNumber);

                List<PdfAnnotation> addedAnnotations = getUpdatedAnnotations(signedAnnotations, finalAnnotations);
                BufferedImage finalScreenshot = finalRevisionReader.generateImageScreenshotWithoutAnnotations(pageNumber,
                        addedAnnotations);

                if (!ImageUtils.imagesEqual(signedScreenshot, finalScreenshot)) {
                    LOG.warn("A visual difference found on page {} between a signed revision and the final document!",
                            pageNumber);
                    visualDifferences.add(new CommonPdfModification(pageNumber));
                }

            } catch (IOException e) {
                LOG.warn("Unable to get visual differences for a page number : {}. Reason : {}",
                        pageNumber, e.getMessage(), e);
            }
        }
        return visualDifferences;
    }

    private List<PdfAnnotation> getUpdatedAnnotations(List<PdfAnnotation> signedAnnotations,
                                                      List<PdfAnnotation> finalAnnotations) {
        final List<PdfAnnotation> updatedAnnotations = new ArrayList<>();
        for (PdfAnnotation annotationBox : finalAnnotations) {
            if (!signedAnnotations.contains(annotationBox)) {
                updatedAnnotations.add(annotationBox);
            }
        }
        return updatedAnnotations;
    }

}
