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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.pdf.PdfObjectModifications;

import java.util.List;

/**
 * The interface contains a necessary information about a PDF visual or structure modifications
 *
 */
public interface PdfModificationDetection {
	
	/**
	 * Returns information about annotations overlapping
	 * 
	 * @return a list of {@link PdfModification}s
	 */
	List<PdfModification> getAnnotationOverlaps();
	
	/**
	 * Returns information about pages with visual differences between signed and final revisions
	 * 
	 * @return a list of {@link PdfModification}s
	 */
	List<PdfModification> getVisualDifferences();
	
	/**
	 * Returns information if there are missing/added pages between the signed and final revisions
	 * 
	 * @return a list of {@link PdfModification}s
	 */
	List<PdfModification> getPageDifferences();

	/**
	 * Returns a filtered collection of modified objects between signed and final document revisions
	 *
	 * @return {@link PdfObjectModifications}
	 */
	PdfObjectModifications getObjectModifications();
	
	/**
	 * Returns information if any modifications have been detected
	 * 
	 * @return TRUE if any modifications have been detected, FALSE otherwise
	 */
	boolean areModificationsDetected();

}
