package eu.europa.esig.dss.pdf.openpdf.visible;

import eu.europa.esig.dss.pdf.visible.AnnotationBox;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBox;

public class AppearenceRectangle implements SignatureFieldBox {

	private final float minX;
	private final float minY;
	private final float maxX;
	private final float maxY;
	
	public AppearenceRectangle(float minX, float minY, float maxX, float maxY) {
		this.minX = minX;
		this.minY = minY;
		this.maxX = maxX;
		this.maxY = maxY;
	}
	
	@Override
	public AnnotationBox toAnnotationBox() {
		return new AnnotationBox(minX, minY, maxX, maxY);
	}

}
