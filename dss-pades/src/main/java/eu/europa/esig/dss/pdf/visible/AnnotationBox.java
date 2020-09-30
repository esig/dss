package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.pades.SignatureFieldParameters;

/**
 * This class defines a PDF annotation dimension and position (note, shape, signature field, etc.)
 *
 */
public class AnnotationBox {
	
	private final float minX;
	private final float maxX;
	private final float minY;
	private final float maxY;
	
	/**
	 * Default constructor
	 * 
	 * @param minX
	 * 			 the lower left X coordinate
	 * @param minY
	 * 			 the lower left Y coordinate
	 * @param maxX
	 * 			 the upper right X coordinate
	 * @param maxY
	 * 			 the upper right Y coordinate
	 */
	public AnnotationBox(float minX, float minY, float maxX, float maxY) {
		this.minX = minX;
		this.minY = minY;
		this.maxX = maxX;
		this.maxY = maxY;
	}
	
	/**
	 * The constructor to instantiate {@code AnnotationBox} from {@code SignatureFieldParameters}
	 * 
	 * @param fieldParameters {@link SignatureFieldParameters}
	 */
	public AnnotationBox(final SignatureFieldParameters fieldParameters) {
		this(fieldParameters.getOriginX(), fieldParameters.getOriginY(), 
				fieldParameters.getOriginX() + fieldParameters.getWidth(), fieldParameters.getOriginY() + fieldParameters.getHeight());
	}

	/**
	 * Returns a lower left X coordinate
	 * 
	 * @return lower left X
	 */
	public float getMinX() {
		return minX;
	}

	/**
	 * Returns a lower left Y coordinate
	 * 
	 * @return lower left Y
	 */
	public float getMinY() {
		return minY;
	}

	/**
	 * Returns an upper right X coordinate
	 * 
	 * @return upper right X
	 */
	public float getMaxX() {
		return maxX;
	}

	/**
	 * Returns an upper right Y coordinate
	 * 
	 * @return upper right Y
	 */
	public float getMaxY() {
		return maxY;
	}

	/**
	 * Returns a width of the box
	 * 
	 * @return width
	 */
	public float getWidth() {
		return maxX - minX;
	}

	/**
	 * Returns a height of the box
	 * 
	 * @return height
	 */
	public float getHeight() {
		return maxY - minY;
	}
	
	/**
	 * Creates a new {@code AnnotationBox} mirrored vertically relatively to the given {@code pageHeight}
	 * 
	 * @param pageHeight the height of a page the annotation box will be created on
	 */
	public AnnotationBox flipVertically(float pageHeight) {
		return new AnnotationBox(minX, pageHeight - maxY, maxX, pageHeight - minY);
	}
	
	/**
	 * Checks if the current {@code AnnotationBox} overlaps with the given {@code box}
	 * 
	 * @param box {@link AnnotationBox} to check against
	 * @return TRUE when the current objects overlaps {@code box}, FALSE otherwise
	 */
	public boolean isOverlap(AnnotationBox box) {
		if (this.getMinX() > box.getMaxX() || box.getMinX() > this.getMaxX()) {
			return false;
		}
		if (this.getMinY() > box.getMaxY() || box.getMinY() > this.getMaxY()) {
			return false;
		}
		return true;
	}

}
