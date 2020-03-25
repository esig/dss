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
package eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;

import java.awt.Dimension;
import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerTextVerticalAlignment;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.utils.Utils;

public class SignatureFieldDimensionAndPositionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureFieldDimensionAndPositionBuilder.class);
	
	private SignatureFieldDimensionAndPosition dimensionAndPosition;
	private final SignatureImageParameters imageParameters;
	private final PDPage page;
	private final PDRectangle pageMediaBox;
	private final PDFont pdFont;
	
    private static final String NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE = "not supported vertical alignment: ";
    private static final String NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE = "not supported horizontal alignment: ";
	
    public SignatureFieldDimensionAndPositionBuilder(SignatureImageParameters imageParameters, PDPage page, PDFont pdFont) {
		this.imageParameters = imageParameters;
		this.page = page;
		this.pageMediaBox = new PDRectangle(page.getMediaBox().getWidth(), page.getMediaBox().getHeight());
		this.pdFont = pdFont;
	}
	
	public SignatureFieldDimensionAndPosition build() throws IOException {
		this.dimensionAndPosition = new SignatureFieldDimensionAndPosition();
		initDpi();
		assignImageBoxDimension();
		alignHorizontally();
		alignVertically();
		rotateSignatureField();
		return this.dimensionAndPosition;
	}
	
	private void initDpi() throws IOException {
		if (imageParameters.getImage() != null) {
			ImageAndResolution imageAndResolution;
			try {
				imageAndResolution = ImageUtils.readDisplayMetadata(imageParameters.getImage());
			} catch (Exception e) {
				LOG.warn("Cannot access the image metadata : {}. Returns default info.", e.getMessage());
				imageAndResolution = new ImageAndResolution(imageParameters.getImage(), imageParameters.getDpi(), imageParameters.getDpi());
			}
			dimensionAndPosition.setImageAndResolution(imageAndResolution);
			dimensionAndPosition.setImageDpi(imageParameters.getDpi());
		}
	}
	
	private void assignImageBoxDimension() throws IOException {
		
		Dimension imageAndDimension = ImageUtils.getImageDimension(imageParameters);
		double imageWidth = imageAndDimension.getWidth();
		double imageHeight = imageAndDimension.getHeight();
		
		if (imageParameters.getWidth() == 0)
			imageWidth *= CommonDrawerUtils.getPageScaleFactor(dimensionAndPosition.getxDpi());
		if (imageParameters.getHeight() == 0)
			imageHeight *= CommonDrawerUtils.getPageScaleFactor(dimensionAndPosition.getyDpi());
		
		double width = imageWidth;
		double height = imageHeight;
		
		SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
		// if text is present
		if (textParameters != null && Utils.isStringNotEmpty(textParameters.getText())) {
			
			// adds an empty space
			imageWidth = toDpiTextPoint(imageWidth, dimensionAndPosition.getxDpi());
			imageHeight = toDpiTextPoint(imageHeight, dimensionAndPosition.getyDpi());
			width = imageWidth;
			height = imageHeight;
			
			// native implementation uses dpi-independent font
			Dimension textBox = computeTextDimension(textParameters);
			float textWidth = (float) textBox.getWidth() * CommonDrawerUtils.getTextScaleFactor(imageParameters.getDpi());
			float textHeight = (float) textBox.getHeight() * CommonDrawerUtils.getTextScaleFactor(imageParameters.getDpi());
			if (imageParameters.getImage() != null) {
				textWidth /= CommonDrawerUtils.getTextScaleFactor(dimensionAndPosition.getxDpi());
				textHeight /= CommonDrawerUtils.getTextScaleFactor(dimensionAndPosition.getyDpi());
			}
			
			switch (imageParameters.getTextParameters().getSignerTextPosition()) {
				case LEFT:
					if (imageParameters.getWidth() == 0) {
						width += imageParameters.getImage() != null || width == 0 ? textWidth : 0;
					} else {
						imageWidth -= imageParameters.getImage() != null || width == 0 ? textWidth : 0;
					}
					if (imageParameters.getHeight() == 0) {
						height = Math.max(height, textHeight);
					}
					dimensionAndPosition.setImageX((float)(width - imageWidth));
					textImageVerticalAlignment(height, imageHeight, textHeight);
					break;
				case RIGHT:
					if (imageParameters.getWidth() == 0) {
						width += imageParameters.getImage() != null || width == 0 ? textWidth : 0;
					} else {
						imageWidth -= imageParameters.getImage() != null || width == 0 ? textWidth : 0;
					}
					if (imageParameters.getHeight() == 0) {
						height = Math.max(height, textHeight);
					}
					dimensionAndPosition.setTextX(toDpiPagePoint(imageWidth, dimensionAndPosition.getxDpi()));
					textImageVerticalAlignment(height, imageHeight, textHeight);
					break;
				case TOP:
					if (imageParameters.getWidth() == 0) {
						width = Math.max(width, textWidth);
					}
					if (imageParameters.getHeight() == 0) {
						height += imageParameters.getImage() != null || height == 0 ? textHeight : 0;
					} else {
						imageHeight -= imageParameters.getImage() != null || height == 0 ? textHeight : 0;
					}
					dimensionAndPosition.setTextY(toDpiPagePoint(imageHeight, dimensionAndPosition.getyDpi()));
					textImageHorizontalAlignment(width, imageWidth, textWidth);
					break;
				case BOTTOM:
					if (imageParameters.getWidth() == 0) {
						width = Math.max(width, textWidth);
					}
					if (imageParameters.getHeight() == 0) {
						height += imageParameters.getImage() != null || height == 0 ? textHeight : 0;
					} else {
						imageHeight -= imageParameters.getImage() != null || height == 0 ? textHeight : 0;
					}
					dimensionAndPosition.setImageY((float)(height - imageHeight));
					textImageHorizontalAlignment(width, imageWidth, textWidth);
					break;
				default:
					break;
				}
			
			dimensionAndPosition.setTextWidth(toDpiPagePoint(textWidth, dimensionAndPosition.getxDpi()));
			dimensionAndPosition.setTextHeight(toDpiPagePoint(textHeight, dimensionAndPosition.getyDpi()));
			dimensionAndPosition.paddingShift(textParameters.getPadding());
			
			width = toDpiPagePoint(width, dimensionAndPosition.getxDpi());
			height = toDpiPagePoint(height, dimensionAndPosition.getyDpi());
		}

		int rotation = ImageRotationUtils.getRotation(imageParameters.getRotation(), page);
		if (ImageRotationUtils.isSwapOfDimensionsRequired(rotation)) {
			double temp = width;
			width = height;
			height = temp;
			pageMediaBox.setUpperRightX(page.getMediaBox().getHeight());
			pageMediaBox.setUpperRightY(page.getMediaBox().getWidth());
		}
		dimensionAndPosition.setGlobalRotation(rotation);
		
		dimensionAndPosition.setImageWidth((float)imageWidth);
		dimensionAndPosition.setImageHeight((float)imageHeight);
		dimensionAndPosition.setBoxWidth((float)width);
		dimensionAndPosition.setBoxHeight((float)height);
	}
	
	private Dimension computeTextDimension(SignatureImageTextParameters textParameters) throws IOException {
		float properSize = CommonDrawerUtils.computeProperSize(textParameters.getFont().getSize(), imageParameters.getDpi());
		properSize *= ImageUtils.getScaleFactor(imageParameters.getZoom()); // scale text block
		String[] lines = textParameters.getText().split("\\r?\\n");
		float width = 0;
		for (String line : lines) {
			float lineWidth = NativePdfBoxDrawerUtils.getTextWidth(pdFont, properSize, line);
			if (lineWidth > width) {
				width = lineWidth;
			}
		}
		float doubleMargin = textParameters.getPadding()*2;
		width += doubleMargin;
		float strHeight = NativePdfBoxDrawerUtils.getTextHeight(pdFont, properSize);
		float height = (strHeight * lines.length) + doubleMargin;
		
		Dimension dimension = new Dimension();
		dimension.setSize(width, height);
		return dimension;
	}

	private void textImageVerticalAlignment(double height, double imageHeight, float textHeight) {
		SignerTextVerticalAlignment verticalAlignment = imageParameters.getTextParameters().getSignerTextVerticalAlignment();
		switch (verticalAlignment) {
			case TOP:
				dimensionAndPosition.setTextY(toDpiPagePoint((height - textHeight), dimensionAndPosition.getyDpi()));
				dimensionAndPosition.setImageY((float)(height - imageHeight));
				break;
			case BOTTOM:
				dimensionAndPosition.setTextY(0);
				dimensionAndPosition.setImageY(0);
				break;
			case MIDDLE:
				dimensionAndPosition.setTextY(toDpiPagePoint((height - textHeight)/2, dimensionAndPosition.getyDpi()));
				dimensionAndPosition.setImageY((float)(height - imageHeight)/2);
				break;
			default:
				throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + verticalAlignment);
		}
	}
	
	private void textImageHorizontalAlignment(double width, double imageWidth, float textWidth) {
		SignerTextHorizontalAlignment horizontalAlignment = imageParameters.getTextParameters().getSignerTextHorizontalAlignment();
		switch (horizontalAlignment) {
			case LEFT:
				dimensionAndPosition.setTextX(0);
				dimensionAndPosition.setImageX(0);
				break;
			case RIGHT:
				dimensionAndPosition.setTextX(toDpiPagePoint((width - textWidth), dimensionAndPosition.getxDpi()));
				dimensionAndPosition.setImageX((float)(width - imageWidth));
				break;
			case CENTER:
				dimensionAndPosition.setTextX(toDpiPagePoint((width - textWidth)/2, dimensionAndPosition.getxDpi()));
				dimensionAndPosition.setImageX((float)(width - imageWidth)/2);
				break;
			default:
				throw new IllegalStateException(NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + horizontalAlignment);
		}
	}
	
	private void alignHorizontally() {
		VisualSignatureAlignmentHorizontal alignmentHorizontal = imageParameters.getVisualSignatureAlignmentHorizontal();
		float boxWidth = dimensionAndPosition.getBoxWidth();
		if (ImageRotationUtils.isSwapOfDimensionsRequired(dimensionAndPosition.getGlobalRotation())) {
			boxWidth = dimensionAndPosition.getBoxHeight();
		}
		float boxX;
		switch (alignmentHorizontal) {
			case LEFT:
			case NONE:
				boxX = imageParameters.getxAxis();
				break;
			case CENTER:
				boxX = (pageMediaBox.getWidth() - boxWidth) / 2;
				break;
			case RIGHT:
				boxX = pageMediaBox.getWidth() - boxWidth - imageParameters.getxAxis();
				break;
			default:
				throw new IllegalStateException(NOT_SUPPORTED_HORIZONTAL_ALIGNMENT_ERROR_MESSAGE + alignmentHorizontal);
		}
		dimensionAndPosition.setBoxX(boxX);
	}
	
	private void alignVertically() {
		VisualSignatureAlignmentVertical alignmentVertical = imageParameters.getVisualSignatureAlignmentVertical();
		float boxHeight = dimensionAndPosition.getBoxHeight();
		if (ImageRotationUtils.isSwapOfDimensionsRequired(dimensionAndPosition.getGlobalRotation())) {
			boxHeight = dimensionAndPosition.getBoxWidth();
		}
		float boxY;
		switch (alignmentVertical) {
		case TOP:
		case NONE:
			boxY = imageParameters.getyAxis();
			break;
		case MIDDLE:
			boxY = (pageMediaBox.getHeight() - boxHeight) / 2;
			break;
		case BOTTOM:
			boxY = pageMediaBox.getHeight() - boxHeight - imageParameters.getyAxis();
			break;
		default:
			throw new IllegalStateException(NOT_SUPPORTED_VERTICAL_ALIGNMENT_ERROR_MESSAGE + alignmentVertical);
		}
		dimensionAndPosition.setBoxY(boxY);
	}
	
	private void rotateSignatureField() {
		switch (dimensionAndPosition.getGlobalRotation()) {
			case ImageRotationUtils.ANGLE_90:
				float boxX = dimensionAndPosition.getBoxX();
				dimensionAndPosition.setBoxX(pageMediaBox.getHeight() - dimensionAndPosition.getBoxY() -
						dimensionAndPosition.getBoxWidth());
				dimensionAndPosition.setBoxY(boxX);
				break;
			case ImageRotationUtils.ANGLE_180:
				dimensionAndPosition.setBoxX(pageMediaBox.getWidth() - dimensionAndPosition.getBoxX() -
						dimensionAndPosition.getBoxWidth());
				dimensionAndPosition.setBoxY(pageMediaBox.getHeight() - dimensionAndPosition.getBoxY() -
						dimensionAndPosition.getBoxHeight());
				break;
			case ImageRotationUtils.ANGLE_270:
				boxX = dimensionAndPosition.getBoxX();
				dimensionAndPosition.setBoxX(dimensionAndPosition.getBoxY());
				dimensionAndPosition.setBoxY(pageMediaBox.getWidth() - boxX -
						dimensionAndPosition.getBoxHeight());
				break;
			case ImageRotationUtils.ANGLE_360:
				// do nothing
				break;
			default:
	            throw new IllegalStateException(ImageRotationUtils.SUPPORTED_ANGLES_ERROR_MESSAGE);
		}
	}
    
	// decrease size
    private float toDpiPagePoint(double x, Integer dpi) {
    	return CommonDrawerUtils.toDpiAxisPoint((float)x, CommonDrawerUtils.getDpi(dpi));
    }
    
    // increase size
    private float toDpiTextPoint(double x, Integer dpi) {
    	return CommonDrawerUtils.computeProperSize((float)x, CommonDrawerUtils.getDpi(dpi));
    }
    
}
