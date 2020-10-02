package eu.europa.esig.dss.pdf;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfModification;
import eu.europa.esig.dss.validation.PdfModificationDetection;

public class PdfModificationDetectionImpl implements PdfModificationDetection {
	
	private List<PdfModification> annotationOverlaps;

	@Override
	public List<PdfModification> getAnnotationOverlaps() {
		return annotationOverlaps;
	}

	public void setAnnotationOverlaps(List<PdfModification> annotationOverlaps) {
		this.annotationOverlaps = annotationOverlaps;
	}

	@Override
	public boolean areModificationsDetected() {
		return Utils.isCollectionNotEmpty(annotationOverlaps);
	}

}
