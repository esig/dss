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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.alert.status.MessageStatus;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to verify the correctness of a new signature field placement within a PDF document
 *
 */
public class PdfSignatureFieldPositionChecker {

    /**
     * This variable set the behavior to follow in case of overlapping a new
     * signature field with existing annotations.
     *
     * Default : ExceptionOnStatusAlert - throw the exception
     */
    private StatusAlert alertOnSignatureFieldOverlap = new ExceptionOnStatusAlert();

    /**
     * This variable allows setting a behavior when
     * a new signature field is created outside the page dimensions
     *
     * Default : ExceptionOnStatusAlert - throw the exception
     */
    private StatusAlert alertOnSignatureFieldOutsidePageDimensions = new ExceptionOnStatusAlert();

    /**
     * This variable allows setting a behavior when
     * a {@code IOException} is thrown on an attempt to read the document properties
     *
     * Default : ExceptionOnStatusAlert - throw the exception
     */
    private StatusAlert alertOnDocumentReadException = new ExceptionOnStatusAlert();

    /**
     * Default constructor to instantiate the checker
     */
    public PdfSignatureFieldPositionChecker() {
        // empty
    }

    /**
     * Sets alert on a signature field overlap with existing fields or/and
     * annotations
     *
     * Default : ExceptionOnStatusAlert - throw the exception
     *
     * @param alertOnSignatureFieldOverlap {@link StatusAlert} to execute
     */
    public void setAlertOnSignatureFieldOverlap(StatusAlert alertOnSignatureFieldOverlap) {
        Objects.requireNonNull(alertOnSignatureFieldOverlap, "StatusAlert cannot be null!");
        this.alertOnSignatureFieldOverlap = alertOnSignatureFieldOverlap;
    }

    /**
     * Sets a behavior to follow when a new signature field is created outside the page's dimensions
     *
     * Default : ExceptionOnStatusAlert - throw the exception
     *
     * @param alertOnSignatureFieldOutsidePageDimensions {@link StatusAlert} to execute
     */
    public void setAlertOnSignatureFieldOutsidePageDimensions(StatusAlert alertOnSignatureFieldOutsidePageDimensions) {
        Objects.requireNonNull(alertOnSignatureFieldOutsidePageDimensions, "StatusAlert cannot be null!");
        this.alertOnSignatureFieldOutsidePageDimensions = alertOnSignatureFieldOutsidePageDimensions;
    }

    /**
     * Sets a behavior to follow when a {@code IOException} is thrown on an attempt to read document properties
     *
     * Default : ExceptionOnStatusAlert - throw the exception
     *
     * @param alertOnDocumentReadException {@link StatusAlert} to execute
     */
    public void setAlertOnDocumentReadException(StatusAlert alertOnDocumentReadException) {
        this.alertOnDocumentReadException = alertOnDocumentReadException;
    }

    /**
     * This method verifies whether {@code annotationBox} can be placed within {@code documentReader}
     * on the page number {@code pageNumber}
     *
     * @param documentReader {@link PdfDocumentReader} document to create new signature field in
     * @param annotationBox {@link AnnotationBox} representing a signature field box to be created
     * @param pageNumber identifying a page number to be created
     */
    public void assertSignatureFieldPositionValid(PdfDocumentReader documentReader, AnnotationBox annotationBox,
                                                  int pageNumber) {
        AnnotationBox pageBox = documentReader.getPageBox(pageNumber);
        checkSignatureFieldAgainstPageDimensions(annotationBox, pageBox);
        List<PdfAnnotation> pdfAnnotations = getAnnotations(documentReader, pageNumber);
        checkSignatureFieldBoxOverlap(annotationBox, pdfAnnotations);
    }

    /**
     * This method verifies whether the {@code signatureFieldBox} overlaps
     * with one of the extracted {@code pdfAnnotations}
     *
     * @param signatureFieldBox {@link AnnotationBox} to verify
     * @param pdfAnnotations a list of {@link AnnotationBox} to verify against
     */
    protected void checkSignatureFieldBoxOverlap(final AnnotationBox signatureFieldBox, List<PdfAnnotation> pdfAnnotations) {
        DefaultPdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();
        if (pdfDifferencesFinder.isAnnotationBoxOverlapping(signatureFieldBox, pdfAnnotations)) {
            alertOnSignatureFieldOverlap();
        }
    }

    /**
     * Executes the alert {@code alertOnSignatureFieldOverlap}
     */
    private void alertOnSignatureFieldOverlap() {
        MessageStatus status = new MessageStatus();
        status.setMessage("The new signature field position overlaps with an existing annotation!");
        alertOnSignatureFieldOverlap.alert(status);
    }

    /**
     * This method verifies whether the {@code signatureFieldBox} is within {@code pageBox}
     *
     * @param signatureFieldBox {@link AnnotationBox} to check
     * @param pageBox {@link AnnotationBox} representing the page's box
     */
    protected void checkSignatureFieldAgainstPageDimensions(final AnnotationBox signatureFieldBox,
                                                            final AnnotationBox pageBox) {
        if (signatureFieldBox.getMinX() < pageBox.getMinX() || signatureFieldBox.getMaxX() > pageBox.getMaxX() ||
                signatureFieldBox.getMinY() < pageBox.getMinY() || signatureFieldBox.getMaxY() > pageBox.getMaxY()) {
            alertOnSignatureFieldOutsidePageDimensions(signatureFieldBox, pageBox);
        }
    }

    private void alertOnSignatureFieldOutsidePageDimensions(final AnnotationBox signatureFieldBox,
                                                            final AnnotationBox pageBox) {
        MessageStatus status = new MessageStatus();
        status.setMessage(String.format("The new signature field position is outside the page dimensions! " +
                        "Signature Field : [minX=%s, maxX=%s, minY=%s, maxY=%s], " +
                        "Page : [minX=%s, maxX=%s, minY=%s, maxY=%s]",
                signatureFieldBox.getMinX(), signatureFieldBox.getMaxX(), signatureFieldBox.getMinY(), signatureFieldBox.getMaxY(),
                pageBox.getMinX(), pageBox.getMaxX(), pageBox.getMinY(), pageBox.getMaxY()));
        alertOnSignatureFieldOutsidePageDimensions.alert(status);
    }

    private List<PdfAnnotation> getAnnotations(PdfDocumentReader documentReader, int pageNumber) {
        try {
            return documentReader.getPdfAnnotations(pageNumber);
        } catch (IOException e) {
            alertOnDocumentReadException(e);
            return Collections.emptyList();
        }
    }

    /**
     * Executes the alert {@code alertOnDocumentReadException}
     */
    private void alertOnDocumentReadException(Exception e) {
        MessageStatus status = new MessageStatus();
        status.setMessage(String.format("An error occurred while reading PDF document! Reason : %s", e.getMessage()));
        alertOnDocumentReadException.alert(status);
    }

}
