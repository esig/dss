package eu.europa.esig.dss.pades.validation;

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
	 * Returns information if any modifications have been detected
	 * 
	 * @return TRUE if any modifications have been detected, FALSE otherwise
	 */
	boolean areModificationsDetected();

}
