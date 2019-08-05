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

import java.awt.Color;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;

/**
 * Parameters for a visible signature creation
 *
 */
public class SignatureImageParameters {

	public static final int DEFAULT_PAGE = 1;

	public static final int NO_SCALING = 100;

	/**
	 * Enum to define image from text vertical alignment in connection with the image
	 */
	public enum SignerTextImageVerticalAlignment {
		TOP, MIDDLE, BOTTOM
	}

	/**
	 * Visual signature horizontal position on the pdf page
	 */
	public enum VisualSignatureAlignmentHorizontal {
		/**
		 * default, x axis is the x coordinate
		 */
		NONE,
		/**
		 * x axis is left padding
		 */
		LEFT,
		/**
		 * x axis automatically calculated
		 */
		CENTER,
		/**
		 * x axis is right padding
		 */
		RIGHT;
	}

	/**
	 * Visual signature vertical position on the pdf page
	 */
	public enum VisualSignatureAlignmentVertical {
		/**
		 * default, y axis is the y coordinate
		 */
		NONE,
		/**
		 * y axis is the top padding
		 */
		TOP,
		/**
		 * y axis automatically calculated
		 */
		MIDDLE,
		/**
		 * y axis is the bottom padding
		 */
		BOTTOM;
	}

	/**
	 * Rotation support
	 *
	 */
	public enum VisualSignatureRotation {
		/**
		 * default, no rotate
		 */
		NONE,
		/**
		 * automatically rotate
		 */
		AUTOMATIC,
		/**
		 * rotate by 90
		 */
		ROTATE_90,
		/**
		 * rotate by 180
		 */
		ROTATE_180,
		/**
		 * rotate by 270
		 */
		ROTATE_270;
	}

	/**
	 * This variable contains the image to use (company logo,...)
	 */
	private DSSDocument image;

	/**
	 * This variable defines the page where the image will appear (1st page by
	 * default)
	 */
	private int page = DEFAULT_PAGE;

	/**
	 * This variable defines the position of the image in the PDF page (X axis)
	 */
	private float xAxis;

	/**
	 * This variable defines the position of the image in the PDF page (Y axis)
	 */
	private float yAxis;
        
        /**
	 * This variable defines the width (in pixel) of the image in the PDF page
	 */
	private int width;


	/**
	  * This variable defines the height (in pixel) of the image in the PDF page
	 */
	private int height;
        
        

	/**
	 * This variable defines a percent to zoom the image (100% means no scaling).
	 * Note: This do not touch zooming of the text representation.
	 */
	private int zoom = NO_SCALING;

	/**
	 * This variable defines the color of the image
	 */
	private Color backgroundColor;

	/**
	 * This variable defines the DPI of the image
	 */
	private Integer dpi;

	/**
	 * This variable is define the image from text vertical alignment in connection with the image<br>
	 * <br>
	 * It has effect when the {@link SignatureImageTextParameters.SignerPosition SignerPosition} is
	 * {@link SignatureImageTextParameters.SignerPosition#LEFT LEFT} or
	 * {@link SignatureImageTextParameters.SignerPosition#RIGHT RIGHT}
	 */
	private SignerTextImageVerticalAlignment signerTextImageVerticalAlignment = SignerTextImageVerticalAlignment.MIDDLE;

	/**
	 * Use rotation on the PDF page, where the visual signature will be
	 */
	private VisualSignatureRotation rotation;

	/**
	 * Horizontal alignment of the visual signature on the pdf page
	 */
	private VisualSignatureAlignmentHorizontal alignmentHorizontal;

	/**
	 * Vertical alignment of the visual signature on the pdf page
	 */
	private VisualSignatureAlignmentVertical alignmentVertical;

	/**
	 * This variable is use to defines the text to generate on the image
	 */
	private SignatureImageTextParameters textParameters;

	public DSSDocument getImage() {
		return image;
	}

	public void setImage(DSSDocument image) {
		this.image = image;
	}

	public float getxAxis() {
		return xAxis;
	}

	public void setxAxis(float xAxis) {
		this.xAxis = xAxis;
	}

	public float getyAxis() {
		return yAxis;
	}

	public void setyAxis(float yAxis) {
		this.yAxis = yAxis;
	}

	public int getZoom() {
		return zoom;
	}

	public void setZoom(int zoom) {
		this.zoom = zoom;
	}
	
	public float getScaleFactor() {
		return zoom / 100f;
	}

	public int getPage() {
		return page;
	}

	public void setPage(int page) {
		this.page = page;
	}
        
    public int getWidth() {
        return width;
    }

    public void setWidth(int width) {
        this.width = width;
    }

    public int getHeight() {
        return height;
    }

    public void setHeight(int height) {
        this.height = height;
    }


	public Color getBackgroundColor() {
		return backgroundColor;
	}

	public void setBackgroundColor(Color backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	public Integer getDpi() {
		return CommonDrawerUtils.getDpi(dpi);
	}

	public void setDpi(Integer dpi) {
		this.dpi = dpi;
	}

	public SignerTextImageVerticalAlignment getSignerTextImageVerticalAlignment() {
		return signerTextImageVerticalAlignment;
	}

	public void setSignerTextImageVerticalAlignment(SignerTextImageVerticalAlignment signerTextImageVerticalAlignment) {
		this.signerTextImageVerticalAlignment = signerTextImageVerticalAlignment;
	}

	public SignatureImageTextParameters getTextParameters() {
		return textParameters;
	}

	public void setTextParameters(SignatureImageTextParameters textParameters) {
		this.textParameters = textParameters;
	}

	public VisualSignatureRotation getRotation() {
		return rotation;
	}

	public void setRotation(VisualSignatureRotation rotation) {
		this.rotation = rotation;
	}

    public SignatureImageParameters.VisualSignatureAlignmentHorizontal getVisualSignatureAlignmentHorizontal() {
        if(alignmentHorizontal == null) {
            alignmentHorizontal = VisualSignatureAlignmentHorizontal.NONE;
        }

        return alignmentHorizontal;
    }

	public void setAlignmentHorizontal(VisualSignatureAlignmentHorizontal alignmentHorizontal) {
		this.alignmentHorizontal = alignmentHorizontal;
	}
	
    public SignatureImageParameters.VisualSignatureAlignmentVertical getVisualSignatureAlignmentVertical() {
        if(alignmentVertical == null) {
            alignmentVertical = VisualSignatureAlignmentVertical.NONE;
        }

        return alignmentVertical;
    }

	public void setAlignmentVertical(VisualSignatureAlignmentVertical alignmentVertical) {
		this.alignmentVertical = alignmentVertical;
	}
}
