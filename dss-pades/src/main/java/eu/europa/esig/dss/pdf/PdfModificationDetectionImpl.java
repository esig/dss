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
import eu.europa.esig.dss.pades.validation.PdfModificationDetection;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * The default implementation to detect modifications in a PDF document
 */
public class PdfModificationDetectionImpl implements PdfModificationDetection {

	/** List of annotation overlaps */
	private List<PdfModification> annotationOverlaps;

	/** List of visual differences between revisions */
	private List<PdfModification> visualDifferences;

	/** List of page amount differences between revisions */
	private List<PdfModification> pageDifferences;

	@Override
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

	@Override
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
	
	@Override
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

	@Override
	public boolean areModificationsDetected() {
		return Utils.isCollectionNotEmpty(annotationOverlaps) || 
				Utils.isCollectionNotEmpty(visualDifferences) || 
				Utils.isCollectionNotEmpty(pageDifferences);
	}

}
