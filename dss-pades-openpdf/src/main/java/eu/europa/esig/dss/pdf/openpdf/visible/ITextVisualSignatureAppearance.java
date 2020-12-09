package eu.europa.esig.dss.pdf.openpdf.visible;

import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.visible.VisualSignatureFieldAppearance;

public class ITextVisualSignatureAppearance implements VisualSignatureFieldAppearance {

	private final float minX;
	private final float minY;
	private final float maxX;
	private final float maxY;
	
	public ITextVisualSignatureAppearance(float minX, float minY, float maxX, float maxY) {
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
