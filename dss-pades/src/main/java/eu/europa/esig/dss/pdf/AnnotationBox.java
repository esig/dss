/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pades.SignatureFieldParameters;

import java.io.Serializable;

/**
 * This class defines a PDF annotation dimension and position (note, shape, signature field, etc.)
 *
 */
public class AnnotationBox implements Serializable {

	private static final long serialVersionUID = -6074495201326993154L;

	/** The lower left X coordinate */
	private final float minX;

	/** The lower left Y coordinate */
	private final float minY;

	/** The upper right X coordinate */
	private final float maxX;

	/** The upper right Y coordinate */
	private final float maxY;
	
	/**
	 * Default constructor (normalizes the provided properties)
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
		this.minX = minX < maxX ? minX : maxX;
		this.minY = minY < maxY ? minY : maxY;
		this.maxX = minX < maxX ? maxX : minX;
		this.maxY = minY < maxY ? maxY : minY;
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
	 * The basis for the method: in used pdf implementations the Y origin is bottom based, 
	 * while in DSS parameters is top-based
	 * 
	 * @param pageHeight the height of a page the annotation box will be created on
	 * @return {@link AnnotationBox}
	 * @deprecated since DSS 6.3. Please use {@code #toPdfPageCoordinates(AnnotationBox pageBox)} method instead.
	 */
	@Deprecated
	public AnnotationBox toPdfPageCoordinates(float pageHeight) {
		return new AnnotationBox(minX, pageHeight - maxY, maxX, pageHeight - minY);
	}

	/**
	 * Creates a new {@code AnnotationBox} mirrored vertically relatively to the given {@code pageBox}
	 * <p>
	 * The basis for the method: in used pdf implementations the Y origin is bottom based,
	 * while in DSS parameters is top-based.
	 * This method also takes into account non-zero upper-left corner coordinates, when applicable.
	 *
	 * @param pageBox {@link AnnotationBox} representing the page's box the new field will be created on
	 * @return {@link AnnotationBox}
	 */
	public AnnotationBox toPdfPageCoordinates(AnnotationBox pageBox) {
		return new AnnotationBox(pageBox.getMinX() + minX, pageBox.getMaxY() - maxY,
				pageBox.getMinX() + maxX, pageBox.getMaxY() - minY);
	}

	/**
	 * Checks if the current {@code AnnotationBox} overlaps with the given {@code pdfAnnotation}
	 * 
	 * @param pdfAnnotation {@link PdfAnnotation} to check against
	 * @return TRUE when the current objects overlaps the annotation, FALSE otherwise
	 */
	public boolean isOverlap(PdfAnnotation pdfAnnotation) {
		return isOverlap(pdfAnnotation.getAnnotationBox());
	}
	
	/**
	 * Checks if the current {@code AnnotationBox} overlaps with the given {@code box}
	 * 
	 * @param box {@link AnnotationBox} to check against
	 * @return TRUE when the current objects overlaps {@code box}, FALSE otherwise
	 */
	public boolean isOverlap(AnnotationBox box) {
		if (this.getMinX() >= box.getMaxX() || box.getMinX() >= this.getMaxX()) {
			return false;
		}
		if (this.getMinY() >= box.getMaxY() || box.getMinY() >= this.getMaxY()) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Float.floatToIntBits(maxX);
		result = prime * result + Float.floatToIntBits(maxY);
		result = prime * result + Float.floatToIntBits(minX);
		result = prime * result + Float.floatToIntBits(minY);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AnnotationBox other = (AnnotationBox) obj;
		if (Float.floatToIntBits(maxX) != Float.floatToIntBits(other.maxX)) {
			return false;
		}
		if (Float.floatToIntBits(maxY) != Float.floatToIntBits(other.maxY)) {
			return false;
		}
		if (Float.floatToIntBits(minX) != Float.floatToIntBits(other.minX)) {
			return false;
		}
		if (Float.floatToIntBits(minY) != Float.floatToIntBits(other.minY)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "AnnotationBox [minX=" + minX + ", minY=" + minY + ", maxX=" + maxX + ", maxY=" + maxY + "]";
	}

}
