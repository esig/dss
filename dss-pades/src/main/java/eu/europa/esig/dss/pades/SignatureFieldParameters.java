/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.pdf.visible.ImageUtils;

import java.io.Serializable;
import java.util.Objects;

/**
 * Parameters which allow to create a new signature field in a PDF document
 */
public class SignatureFieldParameters implements Serializable {

	private static final long serialVersionUID = 4032195150617714778L;

	/** Signature field id/name (optional) */
	private String fieldId;

	/** Page number where the signature field is added */
	private int page = ImageUtils.DEFAULT_FIRST_PAGE;

	/** Coordinate X where to add the signature field (origin is top/left corner) */
	private float originX;

	/** Coordinate Y where to add the signature field (origin is top/left corner) */
	private float originY;

	/** Signature field width */
	private float width;

	/** Signature field height */
	private float height;

	/**
	 * Use rotation on the PDF page, where the signature field will be created
	 */
	private VisualSignatureRotation rotation;

	/**
	 * Default constructor instantiating object with null values
	 */
	public SignatureFieldParameters() {
		// empty
	}

	/**
	 * Gets signature field id
	 * 
	 * @return {@link String} signature field id
	 */
	public String getFieldId() {
		return fieldId;
	}

	/**
	 * Sets a signature field id/name to place a signature into
	 * 
	 * @param fieldId {@link String} signature field id/name
	 */
	public void setFieldId(String fieldId) {
		this.fieldId = fieldId;
	}

	/**
	 * Gets a page where the signature should be placed
	 * 
	 * @return page number
	 */
	public int getPage() {
		return page;
	}

	/**
	 * Sets a page number where the signature field should be placed
	 * 
	 * NOTE: the counting starts from 1 (one) for the first page of the document
	 * 
	 * @param page where the signature field should be placed
	 */
	public void setPage(int page) {
		this.page = page;
	}

	/**
	 * Gets an upper left X coordinate
	 * 
	 * @return upper left X coordinate
	 */
	public float getOriginX() {
		return originX;
	}

	/**
	 * Sets a upper left X coordinate of the signature field
	 * 
	 * @param originX upper left X coordinate
	 */
	public void setOriginX(float originX) {
		this.originX = originX;
	}

	/**
	 * Gets a upper left Y coordinate
	 * 
	 * @return upper left Y coordinate
	 */
	public float getOriginY() {
		return originY;
	}

	/**
	 * Sets a upper left Y coordinate of the signature field
	 * 
	 * @param originY upper left Y coordinate
	 */
	public void setOriginY(float originY) {
		this.originY = originY;
	}

	/**
	 * Gets a width of the signature field
	 * 
	 * @return width
	 */
	public float getWidth() {
		return width;
	}

	/**
	 * Sets a width of the signature field
	 * 
	 * @param width of the signature field
	 */
	public void setWidth(float width) {
		this.width = width;
	}

	/**
	 * Gets a height of the signature field
	 * 
	 * @return height
	 */
	public float getHeight() {
		return height;
	}

	/**
	 * Sets a height of the signature field
	 * 
	 * @param height of the signature field
	 */
	public void setHeight(float height) {
		this.height = height;
	}

	/**
	 * Returns rotation value for a signature field relatively the PDF page
	 *
	 * @return {@link VisualSignatureRotation}
	 */
	public VisualSignatureRotation getRotation() {
		return rotation;
	}

	/**
	 * Sets a rotation value for the signature field relatively the PDF page
	 *
	 * @param rotation
	 *             {@link VisualSignatureRotation}. The following values can be used:
	 *             NONE (DEFAULT value. No rotation is applied. The origin of coordinates begins from the top left corner of a page);
	 *             AUTOMATIC (Rotates a signature field respectively to the page's rotation. Rotates the signature field on the same value as a defined in a PDF page);
	 *             ROTATE_90 (Rotates a signature field for a 90° clockwise. Coordinates' origin begins from top right page corner);
	 *             ROTATE_180 (Rotates a signature field for a 180° clockwise. Coordinates' origin begins from the bottom right page corner);
	 *             ROTATE_270 (Rotates a signature field for a 270° clockwise. Coordinates' origin begins from the bottom left page corner).
	 */
	public void setRotation(VisualSignatureRotation rotation) {
		this.rotation = rotation;
	}

	@Override
	public String toString() {
		return "SignatureFieldParameters [" +
				"fieldId='" + fieldId + '\'' +
				", page=" + page +
				", originX=" + originX +
				", originY=" + originY +
				", width=" + width +
				", height=" + height +
				", rotation=" + rotation +
				']';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		SignatureFieldParameters that = (SignatureFieldParameters) o;
		return page == that.page
				&& Float.compare(originX, that.originX) == 0
				&& Float.compare(originY, that.originY) == 0
				&& Float.compare(width, that.width) == 0
				&& Float.compare(height, that.height) == 0
				&& Objects.equals(fieldId, that.fieldId)
				&& rotation == that.rotation;
	}

	@Override
	public int hashCode() {
		int result = Objects.hashCode(fieldId);
		result = 31 * result + page;
		result = 31 * result + Float.hashCode(originX);
		result = 31 * result + Float.hashCode(originY);
		result = 31 * result + Float.hashCode(width);
		result = 31 * result + Float.hashCode(height);
		result = 31 * result + Objects.hashCode(rotation);
		return result;
	}

}
