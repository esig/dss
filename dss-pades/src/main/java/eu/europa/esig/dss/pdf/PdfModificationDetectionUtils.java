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

import eu.europa.esig.dss.pades.validation.PdfModification;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * The class contains utils for modification detection
 *
 */
public class PdfModificationDetectionUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PdfModificationDetectionUtils.class);

	private PdfModificationDetectionUtils() {
	}

	/**
	 * Returns a list of found annotation overlaps
	 * 
	 * @param reader {@link PdfDocumentReader} the complete PDF document reader
	 * @return a list of {@link PdfModification}s
	 * @throws IOException if an exception occurs
	 */
	public static List<PdfModification> getAnnotationOverlaps(PdfDocumentReader reader) throws IOException {
		List<PdfModification> annotationOverlaps = new ArrayList<>();

		for (int pageNumber = 1; pageNumber <= reader.getNumberOfPages(); pageNumber++) {
			List<PdfAnnotation> pdfAnnotations = reader.getPdfAnnotations(pageNumber);
			Iterator<PdfAnnotation> iterator = pdfAnnotations.iterator();
			while (iterator.hasNext()) {
				PdfAnnotation annotation = iterator.next();
				iterator.remove(); // remove the annotations from the comparison list
				if (isAnnotationBoxOverlapping(annotation.getAnnotationBox(), pdfAnnotations)) {
					annotationOverlaps.add(new PdfModificationImpl(pageNumber));
					break;
				}
			}
		}

		return annotationOverlaps;
	}

	/**
	 * Checks if the given {@code annotationBox} overlaps with
	 * {@code otherAnnotations}
	 * 
	 * @param annotationBox  {@link AnnotationBox} to check
	 * @param pdfAnnotations a list of {@link PdfAnnotation} to validate against
	 * @return TRUE when {@code annotationBox} overlaps with at least one element
	 *         from {@code otherAnnotations} list, FALSE otherwise
	 */
	public static boolean isAnnotationBoxOverlapping(AnnotationBox annotationBox, List<PdfAnnotation> pdfAnnotations) {
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

	/**
	 * Returns a list of visual differences found between signed and final revisions
	 * excluding newly created annotations
	 * 
	 * @param signedRevisionReader {@link PdfDocumentReader} for the signed
	 *                             (covered) revision content
	 * @param finalRevisionReader  {@link PdfDocumentReader} for the originally
	 *                             provided document
	 * @return a list of {@link PdfModification}s
	 * @throws IOException if an exception occurs
	 */
	public static List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
			PdfDocumentReader finalRevisionReader) throws IOException {
		List<PdfModification> visualDifferences = new ArrayList<>();

		for (int pageNumber = 1; pageNumber <= signedRevisionReader.getNumberOfPages()
				&& pageNumber <= finalRevisionReader.getNumberOfPages(); pageNumber++) {

			BufferedImage signedScreenshot = signedRevisionReader.generateImageScreenshot(pageNumber);

			List<PdfAnnotation> signedAnnotations = signedRevisionReader.getPdfAnnotations(pageNumber);
			List<PdfAnnotation> finalAnnotations = finalRevisionReader.getPdfAnnotations(pageNumber);

			List<PdfAnnotation> addedAnnotations = getUpdatedAnnotations(signedAnnotations, finalAnnotations);
			BufferedImage finalScreenshot = finalRevisionReader.generateImageScreenshotWithoutAnnotations(pageNumber,
					addedAnnotations);

			if (!ImageUtils.imagesEqual(signedScreenshot, finalScreenshot)) {
				LOG.warn("A visual difference found on page {} between a signed revision and the final document!",
						pageNumber);
				visualDifferences.add(new PdfModificationImpl(pageNumber));
			}

		}

		return visualDifferences;
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
	public static List<PdfModification> getPagesDifferences(final PdfDocumentReader signedRevisionReader,
			final PdfDocumentReader finalRevisionReader) {
		int signedPages = signedRevisionReader.getNumberOfPages();
		int finalPages = finalRevisionReader.getNumberOfPages();

		int maxNumberOfPages = Math.max(signedPages, finalPages);
		int minNumberOfPages = Math.min(signedPages, finalPages);

		List<PdfModification> missingPages = new ArrayList<>();
		for (int ii = maxNumberOfPages; ii > minNumberOfPages; ii--) {
			missingPages.add(new PdfModificationImpl(ii));
		}

		if (Utils.isCollectionNotEmpty(missingPages)) {
			LOG.warn("The provided PDF file contains {} additional pages against the signed revision!",
					maxNumberOfPages - minNumberOfPages);
		}

		return missingPages;
	}

	private static List<PdfAnnotation> getUpdatedAnnotations(List<PdfAnnotation> signedAnnotations,
			List<PdfAnnotation> finalAnnotations) {
		List<PdfAnnotation> updatesAnnotations = new ArrayList<>();
		for (PdfAnnotation annotationBox : finalAnnotations) {
			if (!signedAnnotations.contains(annotationBox)) {
				updatesAnnotations.add(annotationBox);
			}
		}
		return updatesAnnotations;
	}

}
