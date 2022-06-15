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

import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The class contains utils for modification detection
 *
 */
public class PdfModificationDetectionUtils {

	/** Singleton */
	private static PdfModificationDetectionUtils singleton;

	/** Used to find differences occurred between PDF revisions */
	private PdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();

	/** Used to find differences within internal PDF objects occurred between PDF revisions */
	private PdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();

	/** Used to categorize found object modifications to different groups */
	private PdfObjectModificationsFilter pdfObjectModificationsFilter = new DefaultPdfObjectModificationsFilter();

	/**
	 * Default constructor
	 */
	private PdfModificationDetectionUtils() {
	}

	/**
	 * Returns instance of {@code PdfModificationDetectionUtils}
	 *
	 * @return {@link PdfModificationDetectionUtils}
	 */
	public static PdfModificationDetectionUtils getInstance() {
		if (singleton == null) {
			singleton = new PdfModificationDetectionUtils();
		}
		return singleton;
	}

	/**
	 * Sets the {@code PdfDifferencesFinder} used to find the differences on pages between given PDF revisions.
	 *
	 * Default : {@code DefaultPdfDifferencesFinder}
	 *
	 * @param pdfDifferencesFinder {@link PdfDifferencesFinder}
	 */
	public void setPdfDifferencesFinder(PdfDifferencesFinder pdfDifferencesFinder) {
		Objects.requireNonNull(pdfDifferencesFinder, "PdfDifferencesFinder cannot be null!");
		this.pdfDifferencesFinder = pdfDifferencesFinder;
	}

	/**
	 * Sets the {@code PdfObjectModificationsFinder} used to find the differences between internal PDF objects occurred
	 * between given PDF revisions.
	 *
	 * Default : {@code DefaultPdfObjectModificationsFinder}
	 *
	 * @param pdfObjectModificationsFinder {@link PdfObjectModificationsFinder}
	 */
	public void setPdfObjectModificationsFinder(PdfObjectModificationsFinder pdfObjectModificationsFinder) {
		Objects.requireNonNull(pdfDifferencesFinder, "PdfObjectModificationsFinder cannot be null!");
		this.pdfObjectModificationsFinder = pdfObjectModificationsFinder;
	}

	/**
	 * Sets the {@code PdfObjectModificationsFilter} used to categorize found differences between PDF objects.
	 *
	 * Default : {@code DefaultPdfObjectModificationsFilter}
	 *
	 * @param pdfObjectModificationsFilter {@link PdfObjectModificationsFilter}
	 */
	public void setPdfObjectModificationsFilter(PdfObjectModificationsFilter pdfObjectModificationsFilter) {
		Objects.requireNonNull(pdfDifferencesFinder, "PdfObjectModificationsFilter cannot be null!");
		this.pdfObjectModificationsFilter = pdfObjectModificationsFilter;
	}

	/**
	 * Returns a list of found annotation overlaps
	 *
	 * @param reader {@link PdfDocumentReader} the complete PDF document reader
	 * @return a list of {@link PdfModification}s
	 */
	public List<PdfModification> getAnnotationOverlaps(final PdfDocumentReader reader) {
		return pdfDifferencesFinder.getAnnotationOverlaps(reader);
	}

	/**
	 * Checks if the given {@code annotationBox} overlaps with {@code pdfAnnotations}
	 *
	 * @param annotationBox  {@link AnnotationBox} to check
	 * @param pdfAnnotations a list of {@link PdfAnnotation} to validate against
	 * @return TRUE when {@code annotationBox} overlaps with at least one element
	 *         from {@code otherAnnotations} list, FALSE otherwise
	 */
	public boolean isAnnotationBoxOverlapping(final AnnotationBox annotationBox, final List<PdfAnnotation> pdfAnnotations) {
		return pdfDifferencesFinder.isAnnotationBoxOverlapping(annotationBox, pdfAnnotations);
	}

	/**
	 * Returns a list of missing/added pages between signed and final revisions
	 *
	 * @param signedRevisionReader {@link PdfDocumentReader} for the signed
	 *                             (covered) revision content
	 * @param finalRevisionReader  {@link PdfDocumentReader} for the originally
	 *                             provided document
	 * @return a list of {@link PdfModification}s
	 */
	public List<PdfModification> getPagesDifferences(final PdfDocumentReader signedRevisionReader,
													 final PdfDocumentReader finalRevisionReader) {
		return pdfDifferencesFinder.getPagesDifferences(signedRevisionReader, finalRevisionReader);
	}

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
	public List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
													  final PdfDocumentReader finalRevisionReader) {
		return pdfDifferencesFinder.getVisualDifferences(signedRevisionReader, finalRevisionReader);
	}

	/**
	 * This method returns {@code PdfObjectModifications} containing categorized object modifications found
	 * between two given revisions.
	 *
	 * @param signedRevisionReader {@link PdfDocumentReader} for the signed
	 *                             (covered) revision content
	 * @param finalRevisionReader  {@link PdfDocumentReader} for the originally
	 *                             provided document
	 * @return {@link PdfObjectModifications}
	 */
	public PdfObjectModifications getObjectModifications(final PdfDocumentReader signedRevisionReader,
														 final PdfDocumentReader finalRevisionReader) {
		final Set<ObjectModification> objectModifications = pdfObjectModificationsFinder.find(
				signedRevisionReader, finalRevisionReader);
		return pdfObjectModificationsFilter.filter(objectModifications);
	}

}
