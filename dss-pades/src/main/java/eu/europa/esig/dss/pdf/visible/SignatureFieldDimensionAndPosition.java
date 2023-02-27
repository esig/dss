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
package eu.europa.esig.dss.pdf.visible;

import eu.europa.esig.dss.pdf.AnnotationBox;

/**
 * Defines visual signature field appearance parameters
 *
 */
public class SignatureFieldDimensionAndPosition implements VisualSignatureFieldAppearance {

	private static final long serialVersionUID = 5513776649702929990L;

	/** Upper left X coordinate of the signature bounding box */
	private float boxX = 0;
	/** Upper left Y coordinate of the signature bounding box */
	private float boxY = 0;
	/** Width of the signature bounding box */
	private float boxWidth = 0;
	/** Height of the signature bounding box */
	private float boxHeight = 0;

	/** Upper left X coordinate of the image */
	private float imageX = 0;
	/** Upper left Y coordinate of the image */
	private float imageY = 0;
	/** Width of the image */
	private float imageWidth = 0;
	/** Height of the image */
	private float imageHeight = 0;

	/** Upper left X coordinate of the image bounding box */
	private float imageBoxX = 0;
	/** Upper left Y coordinate of the image bounding box */
	private float imageBoxY = 0;
	/** Width of the image bounding box */
	private float imageBoxWidth = 0;
	/** Height of the image bounding box */
	private float imageBoxHeight = 0;

	/** Upper left X coordinate of the text */
	private float textX = 0;
	/** Upper left Y coordinate of the text */
	private float textY = 0;
	/** Width of the text */
	private float textWidth = 0;
	/** Height of the text */
	private float textHeight = 0;

	/** Upper left X coordinate of the text bounding box */
	private float textBoxX = 0;
	/** Upper left Y coordinate of the text bounding box */
	private float textBoxY = 0;
	/** Width the text bounding box */
	private float textBoxWidth = 0;
	/** Height the text bounding box */
	private float textBoxHeight = 0;

	/** The text string */
	private String text = null;
	/** The text size */
	private float textSize = 0;

	/** The global rotation of the page */
	private int globalRotation;

	/** ImageResolution */
	private ImageResolution imageResolution;

	/**
	 * Default constructor instantiating object with null parameters
	 */
	public SignatureFieldDimensionAndPosition() {
		// empty
	}

	/**
	 * Gets upper left X coordinate of the signature bounding box
	 *
	 * @return upper left X coordinate
	 */
	public float getBoxX() {
		return boxX;
	}

	/**
	 * Sets upper left X coordinate of the signature bounding box
	 *
	 * @param boxX upper left X coordinate
	 */
	public void setBoxX(float boxX) {
		this.boxX = boxX;
	}

	/**
	 * Gets upper left Y coordinate of the signature bounding box
	 *
	 * @return upper left Y coordinate
	 */
	public float getBoxY() {
		return boxY;
	}

	/**
	 * Sets upper left Y coordinate of the signature bounding box
	 *
	 * @param boxY upper left Y coordinate
	 */
	public void setBoxY(float boxY) {
		this.boxY = boxY;
	}

	/**
	 * Gets width of the signature bounding box
	 *
	 * @return width
	 */
	public float getBoxWidth() {
		return boxWidth;
	}

	/**
	 * Sets width of the signature bounding box
	 *
	 * @param boxWidth width
	 */
	public void setBoxWidth(float boxWidth) {
		this.boxWidth = boxWidth;
	}

	/**
	 * Gets height of the signature bounding box
	 *
	 * @return height
	 */
	public float getBoxHeight() {
		return boxHeight;
	}

	/**
	 * Sets height of the signature bounding box
	 *
	 * @param boxHeight height
	 */
	public void setBoxHeight(float boxHeight) {
		this.boxHeight = boxHeight;
	}

	/**
	 * Gets upper left X coordinate of the image
	 *
	 * @return upper left X coordinate
	 */
	public float getImageX() {
		return imageX;
	}

	/**
	 * Sets upper left X coordinate of the image
	 *
	 * @param imageX upper left X coordinate
	 */
	public void setImageX(float imageX) {
		this.imageX = imageX;
	}

	/**
	 * Gets upper left Y coordinate of the image
	 *
	 * @return upper left Y coordinate
	 */
	public float getImageY() {
		return imageY;
	}

	/**
	 * Sets upper left Y coordinate of the image
	 *
	 * @param imageY upper left Y coordinate
	 */
	public void setImageY(float imageY) {
		this.imageY = imageY;
	}

	/**
	 * Gets width of the image
	 *
	 * @return width
	 */
	public float getImageWidth() {
		return imageWidth;
	}

	/**
	 * Sets width of the image
	 *
	 * @param imageWidth width
	 */
	public void setImageWidth(float imageWidth) {
		this.imageWidth = imageWidth;
	}

	/**
	 * Gets height of the image
	 *
	 * @return height
	 */
	public float getImageHeight() {
		return imageHeight;
	}

	/**
	 * Sets height of the image
	 *
	 * @param imageHeight height
	 */
	public void setImageHeight(float imageHeight) {
		this.imageHeight = imageHeight;
	}

	/**
	 * Gets upper left X coordinate of the image boundary box
	 *
	 * @return upper left X coordinate
	 */
	public float getImageBoxX() {
		return imageBoxX;
	}

	/**
	 * Sets upper left X coordinate of the image boundary box
	 *
	 * @param imageBoxX upper left X coordinate
	 */
	public void setImageBoxX(float imageBoxX) {
		this.imageBoxX = imageBoxX;
	}

	/**
	 * Gets upper left Y coordinate of the image boundary box
	 *
	 * @return upper left Y coordinate
	 */
	public float getImageBoxY() {
		return imageBoxY;
	}

	/**
	 * Sets upper left Y coordinate of the image boundary box
	 *
	 * @param imageBoxY upper left Y coordinate
	 */
	public void setImageBoxY(float imageBoxY) {
		this.imageBoxY = imageBoxY;
	}

	/**
	 * Gets width of the image boundary box
	 *
	 * @return width
	 */
	public float getImageBoxWidth() {
		return imageBoxWidth;
	}

	/**
	 * Sets width of the image boundary box
	 *
	 * @param imageBoxWidth width
	 */
	public void setImageBoxWidth(float imageBoxWidth) {
		this.imageBoxWidth = imageBoxWidth;
	}

	/**
	 * Gets height of the image boundary box
	 *
	 * @return height
	 */
	public float getImageBoxHeight() {
		return imageBoxHeight;
	}

	/**
	 * Sets height of the image boundary box
	 *
	 * @param imageBoxHeight height
	 */
	public void setImageBoxHeight(float imageBoxHeight) {
		this.imageBoxHeight = imageBoxHeight;
	}

	/**
	 * Gets upper left X coordinate of the text
	 *
	 * @return upper left X coordinate
	 */
	public float getTextX() {
		return textX;
	}

	/**
	 * Sets upper left X coordinate of the text
	 *
	 * @param textX upper left X coordinate
	 */
	public void setTextX(float textX) {
		this.textX = textX;
	}

	/**
	 * Gets upper left Y coordinate of the text
	 *
	 * @return upper left Y coordinate
	 */
	public float getTextY() {
		return textY;
	}

	/**
	 * Sets upper left Y coordinate of the text
	 *
	 * @param textY upper left Y coordinate
	 */
	public void setTextY(float textY) {
		this.textY = textY;
	}

	/**
	 * Gets width of the text
	 *
	 * @return width
	 */
	public float getTextWidth() {
		return textWidth;
	}

	/**
	 * Sets width of the text
	 *
	 * @param textWidth width
	 */
	public void setTextWidth(float textWidth) {
		this.textWidth = textWidth;
	}

	/**
	 * Gets height of the text
	 *
	 * @return height
	 */
	public float getTextHeight() {
		return textHeight;
	}


	/**
	 * Sets height of the text
	 *
	 * @param textHeight height
	 */
	public void setTextHeight(float textHeight) {
		this.textHeight = textHeight;
	}

	/**
	 * Gets upper left X coordinate of the text boundary box
	 *
	 * @return upper left X coordinate
	 */
	public float getTextBoxX() {
		return textBoxX;
	}

	/**
	 * Sets upper left X coordinate of the text boundary box
	 *
	 * @param textBoxX upper left X coordinate
	 */
	public void setTextBoxX(float textBoxX) {
		this.textBoxX = textBoxX;
	}

	/**
	 * Gets upper left Y coordinate of the text boundary box
	 *
	 * @return upper left Y coordinate
	 */
	public float getTextBoxY() {
		return textBoxY;
	}

	/**
	 * Sets upper left Y coordinate of the text boundary box
	 *
	 * @param textBoxY upper left Y coordinate
	 */
	public void setTextBoxY(float textBoxY) {
		this.textBoxY = textBoxY;
	}

	/**
	 * Gets width of the text boundary box
	 *
	 * @return width
	 */
	public float getTextBoxWidth() {
		return textBoxWidth;
	}

	/**
	 * Sets width of the text boundary box
	 *
	 * @param textBoxWidth width
	 */
	public void setTextBoxWidth(float textBoxWidth) {
		this.textBoxWidth = textBoxWidth;
	}

	/**
	 * Gets height of the text boundary box
	 *
	 * @return height
	 */
	public float getTextBoxHeight() {
		return textBoxHeight;
	}

	/**
	 * Sets height of the text boundary box
	 *
	 * @param textBoxHeight height
	 */
	public void setTextBoxHeight(float textBoxHeight) {
		this.textBoxHeight = textBoxHeight;
	}

	/**
	 * Gets test string
	 *
	 * @return {@link String}
	 */
	public String getText() {
		return text;
	}

	/**
	 * Sets text string
	 *
	 * @param text {@link String}
	 */
	public void setText(String text) {
		this.text = text;
	}

	/**
	 * Gets text size
	 *
	 * @return text size
	 */
	public float getTextSize() {
		return textSize;
	}

	/**
	 * Sets text size
	 * @param textSize text size
	 */
	public void setTextSize(float textSize) {
		this.textSize = textSize;
	}

	/**
	 * Gets global signature field rotation
	 *
	 * @return rotation
	 */
	public int getGlobalRotation() {
		return globalRotation;
	}

	/**
	 * Sets global signature field rotation
	 *
	 * @param globalRotation rotation
	 */
	public void setGlobalRotation(int globalRotation) {
		this.globalRotation = globalRotation;
	}

	/**
	 * Gets ImageResolution
	 *
	 * @return {@link ImageResolution}
	 */
	public ImageResolution getImageResolution() {
		return imageResolution;
	}

	/**
	 * Sets ImageResolution
	 *
	 * @param imageResolution {@link ImageResolution}
	 */
	public void setImageResolution(ImageResolution imageResolution) {
		this.imageResolution = imageResolution;
	}

	@Override
	public AnnotationBox getAnnotationBox() {
		return new AnnotationBox(boxX, boxY, boxX + boxWidth, boxY + boxHeight);
	}
	
}
