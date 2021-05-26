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

public class SignatureFieldDimensionAndPosition implements VisualSignatureFieldAppearance {
	
	private float boxX = 0;
	private float boxY = 0;
	private float boxWidth = 0;
	private float boxHeight = 0;
	
	private float imageX = 0;
	private float imageY = 0;
	private float imageWidth = 0;
	private float imageHeight = 0;
	
	private float textX = 0;
	private float textY = 0;
	private float textWidth = 0;
	private float textHeight = 0;
	
	private float textBoxX = 0;
	private float textBoxY = 0;
	private float textBoxWidth = 0;
	private float textBoxHeight = 0;
	
	private int globalRotation;

	private ImageResolution imageResolution;

	public float getBoxX() {
		return boxX;
	}
	
	public void setBoxX(float boxX) {
		this.boxX = boxX;
	}
	
	public float getBoxY() {
		return boxY;
	}
	
	public void setBoxY(float boxY) {
		this.boxY = boxY;
	}
	
	public float getBoxWidth() {
		return boxWidth;
	}
	
	public void setBoxWidth(float boxWidth) {
		this.boxWidth = boxWidth;
	}
	
	public float getBoxHeight() {
		return boxHeight;
	}
	
	public void setBoxHeight(float boxHeight) {
		this.boxHeight = boxHeight;
	}
	
	public float getImageX() {
		return imageX;
	}
	
	public void setImageX(float imageX) {
		this.imageX = imageX;
	}
	
	public float getImageY() {
		return imageY;
	}
	
	public void setImageY(float imageY) {
		this.imageY = imageY;
	}
	
	public float getImageHeight() {
		return imageHeight;
	}
	
	public void setImageHeight(float imageHeight) {
		this.imageHeight = imageHeight;
	}
	
	public float getImageWidth() {
		return imageWidth;
	}
	
	public void setImageWidth(float imageWidth) {
		this.imageWidth = imageWidth;
	}
	
	public float getTextX() {
		return textX;
	}
	
	public void setTextX(float textX) {
		this.textX = textX;
	}
	
	public float getTextY() {
		return textY;
	}
	
	public void setTextY(float textY) {
		this.textY = textY;
	}
	
	public float getTextWidth() {
		return textWidth;
	}
	
	public void setTextWidth(float textWidth) {
		this.textWidth = textWidth;
	}
	
	public float getTextHeight() {
		return textHeight;
	}
	
	public void setTextHeight(float textHeight) {
		this.textHeight = textHeight;
	}

	public float getTextBoxX() {
		return textBoxX;
	}
	
	public void setTextBoxX(float textBoxX) {
		this.textBoxX = textBoxX;
	}
	
	public float getTextBoxY() {
		return textBoxY;
	}
	
	public void setTextBoxY(float textBoxY) {
		this.textBoxY = textBoxY;
	}
	
	public float getTextBoxWidth() {
		return textBoxWidth;
	}
	
	public void setTextBoxWidth(float textBoxWidth) {
		this.textBoxWidth = textBoxWidth;
	}
	
	public float getTextBoxHeight() {
		return textBoxHeight;
	}
	
	public void setTextBoxHeight(float textBoxHeight) {
		this.textBoxHeight = textBoxHeight;
	}

	public int getGlobalRotation() {
		return globalRotation;
	}

	public void setGlobalRotation(int globalRotation) {
		this.globalRotation = globalRotation;
	}

	public ImageResolution getImageResolution() {
		return imageResolution;
	}

	public void setImageResolution(ImageResolution imageResolution) {
		this.imageResolution = imageResolution;
	}

	@Override
	public AnnotationBox getAnnotationBox() {
		return new AnnotationBox(boxX, boxY, boxX + boxWidth, boxY + boxHeight);
	}
	
}
