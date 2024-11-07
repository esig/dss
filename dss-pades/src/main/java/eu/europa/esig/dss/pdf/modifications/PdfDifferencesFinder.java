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
package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.PdfAnnotation;
import eu.europa.esig.dss.pdf.PdfDocumentReader;

import java.util.List;

/**
 * This interface is used to encounter differences in pages between given PDF revisions.
 *
 */
public interface PdfDifferencesFinder {

    /**
     * Returns a list of found annotation overlaps
     *
     * @param reader {@link PdfDocumentReader} the complete PDF document reader
     * @return a list of {@link PdfModification}s
     */
    List<PdfModification> getAnnotationOverlaps(final PdfDocumentReader reader);

    /**
     * Checks if the given {@code annotationBox} overlaps with {@code pdfAnnotations}
     *
     * @param annotationBox  {@link AnnotationBox} to check
     * @param pdfAnnotations a list of {@link PdfAnnotation} to validate against
     * @return TRUE when {@code annotationBox} overlaps with at least one element
     *         from {@code otherAnnotations} list, FALSE otherwise
     */
    boolean isAnnotationBoxOverlapping(final AnnotationBox annotationBox, final List<PdfAnnotation> pdfAnnotations);

    /**
     * Returns a list of missing/added pages between signed and final revisions
     *
     * @param signedRevisionReader {@link PdfDocumentReader} for the signed
     *                             (covered) revision content
     * @param finalRevisionReader  {@link PdfDocumentReader} for the originally
     *                             provided document
     * @return a list of {@link PdfModification}s
     */
    List<PdfModification> getPagesDifferences(final PdfDocumentReader signedRevisionReader,
                                              final PdfDocumentReader finalRevisionReader);

    /**
     * Returns a list of visual differences found between signed and final revisions
     * excluding newly created annotations
     *
     * @param signedRevisionReader {@link PdfDocumentReader} for the signed
     *                             (covered) revision content
     * @param finalRevisionReader  {@link PdfDocumentReader} for the originally
     *                             provided document
     * @return a list of {@link PdfModification}s
     */
    List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
                                               final PdfDocumentReader finalRevisionReader);

}
