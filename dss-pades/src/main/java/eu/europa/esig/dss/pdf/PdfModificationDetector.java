package eu.europa.esig.dss.pdf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import eu.europa.esig.dss.validation.PdfModification;
import eu.europa.esig.dss.validation.PdfModificationDetection;

public class PdfModificationDetector {
	
	private final PdfDocumentReader reader;
	
	/**
	 * The default constructor
	 * 
	 * @param reader {@link PdfDocumentReader}
	 */
	public PdfModificationDetector(final PdfDocumentReader reader) {
		this.reader = reader;
	}
	
	/**
	 * Analyzes the current document
	 * 
	 * @return {@link PdfModificationDetection}
	 * @throws IOException if an exception occurs
	 */
	public PdfModificationDetection analizeDocument() throws IOException {
		PdfModificationDetectionImpl pdfModificationDetection = new PdfModificationDetectionImpl();
		
		pdfModificationDetection.setAnnotationOverlaps(getAnnotationOverlaps());
		// TODO: add other checks
		
		return pdfModificationDetection;
	}
	
	private List<PdfModification> getAnnotationOverlaps() throws IOException {
		List<PdfModification> annotationOverlaps = new ArrayList<>();
		
		for (int pageNumber = 1; pageNumber <= reader.getPageNumber(); pageNumber++) {
			List<AnnotationBox> annotationBoxes = reader.getAnnotationBoxes(pageNumber);
			Iterator<AnnotationBox> iterator = annotationBoxes.iterator();
			while (iterator.hasNext()) {
				AnnotationBox annotationBox = iterator.next();
				iterator.remove(); // remove the annotations from the comparison list
				if (isAnnotationBoxOverlapping(annotationBox, annotationBoxes)) {
					annotationOverlaps.add(new PdfAnnotationOverlap(pageNumber));
					break;
				}
			}
		}
		
		return annotationOverlaps;
	}
	
	/**
	 * Checks if the given {@code annotationBox} overlaps with {@code otherAnnotations}
	 * 
	 * @param annotationBox {@link AnnotationBox} to check
	 * @param otherAnnotations a list of {@link AnnotationBox} to validate against
	 * @return TRUE when {@code annotationBox} overlaps with at least one element from {@code otherAnnotations} list, FALSE otherwise
	 */
	public static boolean isAnnotationBoxOverlapping(AnnotationBox annotationBox, List<AnnotationBox> otherAnnotations) {
		if (annotationBox.getWidth() == 0 || annotationBox.getHeight() == 0) {
			// invisible field
			return false;
		}
		for (AnnotationBox otherAnnotation : otherAnnotations) {
			if (annotationBox.isOverlap(otherAnnotation)) {
				return true;
			}
		}
		return false;
	}

}
