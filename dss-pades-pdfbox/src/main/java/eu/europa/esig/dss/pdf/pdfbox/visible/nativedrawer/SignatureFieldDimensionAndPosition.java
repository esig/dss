package eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;

import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;

public class SignatureFieldDimensionAndPosition {
	
	private float boxX = 0;
	private float boxY = 0;
	private float boxWidth = 0;
	private float boxHeight = 0;
	
	private float imageX = 0;
	private float imageY = 0;
	
	private float textX = 0;
	private float textY = 0;
	private float textWidth = 0;
	private float textHeight = 0;
	
	private ImageAndResolution imageAndResolution;
	
	private static final int DEFAULT_DPI = 72;
	private static final int DEFAULT_TEXT_DPI = 300;
	
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
	
	public void setImageAndResolution(ImageAndResolution imageAndResolution) {
		this.imageAndResolution = imageAndResolution;
	}
	
	public int getxDpi() {
		if (imageAndResolution != null) {
			return imageAndResolution.getxDpi();
		} else {
			return DEFAULT_TEXT_DPI;
		}
	}
	
	public int getyDpi() {
		if (imageAndResolution != null) {
			return imageAndResolution.getyDpi();
		} else {
			return DEFAULT_TEXT_DPI;
		}
	}
	
	public float getxDpiRatio() {
		return (float) DEFAULT_DPI / getxDpi();
	}
	
	public float getyDpiRatio() {
		return (float) DEFAULT_DPI / getyDpi();
	}
	
	public void marginShift(float margin) {
		this.textX += CommonDrawerUtils.toDpiAxisPoint(margin / CommonDrawerUtils.getScaleFactor(getxDpi()), getxDpi());
		this.textY -= CommonDrawerUtils.toDpiAxisPoint(margin / CommonDrawerUtils.getScaleFactor(getyDpi()), getyDpi()); // because PDF starts to count from bottom
	}
	
}
