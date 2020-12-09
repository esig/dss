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
