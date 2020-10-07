package eu.europa.esig.dss.pdf;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfModification;
import eu.europa.esig.dss.validation.PdfModificationDetection;

public class PdfModificationDetectionImpl implements PdfModificationDetection {
	
	private List<PdfModification> annotationOverlaps;
	private List<PdfModification> visualDifferences;

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
	public boolean areModificationsDetected() {
		return Utils.isCollectionNotEmpty(annotationOverlaps) || Utils.isCollectionNotEmpty(visualDifferences);
	}

}
