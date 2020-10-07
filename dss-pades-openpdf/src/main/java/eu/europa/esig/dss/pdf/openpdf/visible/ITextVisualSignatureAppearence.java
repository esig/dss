package eu.europa.esig.dss.pdf.openpdf.visible;

import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.visible.VisualSignatureFieldAppearence;

public class ITextVisualSignatureAppearence implements VisualSignatureFieldAppearence {

	private final float minX;
	private final float minY;
	private final float maxX;
	private final float maxY;
	
	public ITextVisualSignatureAppearence(float minX, float minY, float maxX, float maxY) {
		this.minX = minX;
		this.minY = minY;
		this.maxX = maxX;
		this.maxY = maxY;
	}
	
	@Override
	public AnnotationBox getAnnotationBox() {
		return new AnnotationBox(minX, minY, maxX, maxY);
	}

}
