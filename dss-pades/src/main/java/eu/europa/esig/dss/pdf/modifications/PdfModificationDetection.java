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

import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * The interface contains necessary information about a PDF visual or structure modifications
 *
 */
public class PdfModificationDetection {

	/** List of annotation overlaps */
	private List<PdfModification> annotationOverlaps;

	/** List of visual differences between revisions */
	private List<PdfModification> visualDifferences;

	/** List of page amount differences between revisions */
	private List<PdfModification> pageDifferences;

	/** Filtered collection of {@code ObjectModification}s between a signed and final revisions */
	private PdfObjectModifications objectModifications;

	/**
	 * Returns information about annotations overlapping
	 *
	 * @return a list of {@link PdfModification}s
	 */
	public List<PdfModification> getAnnotationOverlaps() {
		return annotationOverlaps;
	}

	/**
	 * Sets annotation overlaps
	 *
	 * @param annotationOverlaps a list of {@link PdfModification}s
	 */
	public void setAnnotationOverlaps(List<PdfModification> annotationOverlaps) {
		this.annotationOverlaps = annotationOverlaps;
	}

	/**
	 * Returns information if there are missing/added pages between the signed and final revisions
	 *
	 * @return a list of {@link PdfModification}s
	 */
	public List<PdfModification> getPageDifferences() {
		return pageDifferences;
	}

	/**
	 * Sets page differences (for missing/added pages)
	 *
	 * @param pageDifferences a list of {@link PdfModification}s
	 */
	public void setPageDifferences(List<PdfModification> pageDifferences) {
		this.pageDifferences = pageDifferences;
	}

	/**
	 * Returns information about pages with visual differences between signed and final revisions
	 *
	 * @return a list of {@link PdfModification}s
	 */
	public List<PdfModification> getVisualDifferences() {
		return visualDifferences;
	}

	/**
	 * Sets visual differences
	 *
	 * @param visualDifferences a list of {@link PdfModification}s
	 */
	public void setVisualDifferences(List<PdfModification> visualDifferences) {
		this.visualDifferences = visualDifferences;
	}

	/**
	 * Returns a filtered collection of modified objects between signed and final document revisions
	 *
	 * @return {@link PdfObjectModifications}
	 */
	public PdfObjectModifications getObjectModifications() {
		return objectModifications;
	}

	/**
	 * Sets a collection of filtered object modifications
	 *
	 * @param objectModifications {@link PdfObjectModifications}
	 */
	public void setObjectModifications(PdfObjectModifications objectModifications) {
		this.objectModifications = objectModifications;
	}

	/**
	 * Returns information if any modifications have been detected
	 *
	 * @return TRUE if any modifications have been detected, FALSE otherwise
	 */
	public boolean areModificationsDetected() {
		return Utils.isCollectionNotEmpty(annotationOverlaps) ||
				Utils.isCollectionNotEmpty(visualDifferences) ||
				Utils.isCollectionNotEmpty(pageDifferences) ||
				!objectModifications.isEmpty();
	}

}
