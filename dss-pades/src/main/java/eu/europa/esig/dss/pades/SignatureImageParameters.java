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
	 * Use rotation on the PDF page, where the visual signature will be
	 */
	private VisualSignatureRotation rotation;

	/**
	 * Horizontal alignment of the visual signature on the pdf page
	 */
	private VisualSignatureAlignmentHorizontal alignmentHorizontal = VisualSignatureAlignmentHorizontal.NONE;

	/**
	 * Vertical alignment of the visual signature on the pdf page
	 */
	private VisualSignatureAlignmentVertical alignmentVertical = VisualSignatureAlignmentVertical.NONE;

	/**
	 * This variable is use to defines the text to generate on the image
	 */
	private SignatureImageTextParameters textParameters;

	/**
	 * Returns a {@code DSSDocument} image defined for displaying on the signature field
	 * @return {@link DSSDocument} image
	 */
	public DSSDocument getImage() {
		return image;
	}

	/**
	 * Allows to set a custom image to display on a signature field
	 * @param image {@link DSSDocument}
	 */
	public void setImage(DSSDocument image) {
		this.image = image;
	}

	/**
	 * Returns an absolute margin of the signature field by X axis
	 * @return X axis float value
	 */
	public float getxAxis() {
		return xAxis;
	}

	/**
	 * Allows specifying of an absolute margin for the signature field by X axis
	 * @param xAxis {@code float} margin
	 */
	public void setxAxis(float xAxis) {
		this.xAxis = xAxis;
	}

	/**
	 * Returns an absolute margin of the signature field by Y axis
	 * @return Y axis float value
	 */
	public float getyAxis() {
		return yAxis;
	}

	/**
	 * Allows specifying of an absolute margin for the signature field by Y axis
	 * @param yAxis {@code float} margin
	 */
	public void setyAxis(float yAxis) {
		this.yAxis = yAxis;
	}

	/**
	 * Returns the defined Zoom value in percentage
	 * @return {@code int} zoom
	 */
	public int getZoom() {
		return zoom;
	}

	/**
	 * Defines the signature field zoom in percentage (default value = 100)
	 * @param zoom {@code int} zoom value
	 */
	public void setZoom(int zoom) {
		this.zoom = zoom;
	}

	/**
	 * Returns a page number where the signature field must be placed
	 * @return {@code int} page number
	 */
	public int getPage() {
		return page;
	}

	/**
	 * Defines a number of page in the document where the signature field must be placed.
	 * The counting of pages starts from 1 (the first page) (default value = 1)
	 * NOTE: the page must exist in the document!
	 * @param page {@code int} page number
	 */
	public void setPage(int page) {
		this.page = page;
	}
    
	/**
	 * Returns a specified width of the signature field
	 * @return {@code int} width value
	 */
    public int getWidth() {
        return width;
    }

    /**
     * Defines a custom width for the signature field in pixels
     * @param width {@code int} width value
     */
    public void setWidth(int width) {
        this.width = width;
    }

	/**
	 * Returns a specified height of the signature field
	 * @return {@code int} height value
	 */
    public int getHeight() {
        return height;
    }

    /**
     * Defines a custom height for the signature field in pixels
     * @param height {@code int} height value
     */
    public void setHeight(int height) {
        this.height = height;
    }

    /**
     * Returns a specified background color for the signature field
     * @return {@link Color} background color
     */
	public Color getBackgroundColor() {
		return backgroundColor;
	}

	/**
	 * Sets the background color for the signature field
	 * @param backgroundColor {@link Color} to set
	 */
	public void setBackgroundColor(Color backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	/**
	 * Returns a defined DPI value
	 * Note: can be null
	 * @return {@link Integer} dpi value
	 */
	public Integer getDpi() {
		return CommonDrawerUtils.getDpi(dpi);
	}

	/**
	 * Sets an expected DPI value. If NULL the default dpi of the provided image is applied.
	 * Note: images with a lower DPI will take more space on a PDF page
	 * @param dpi {@link Integer} dpi value
	 */
	public void setDpi(Integer dpi) {
		this.dpi = dpi;
	}

	/**
	 * Returns text parameters
	 * @return {@link SignatureImageTextParameters}
	 */
	public SignatureImageTextParameters getTextParameters() {
		return textParameters;
	}

	/**
	 * Sets text parameters
	 * @param textParameters {@link SignatureImageTextParameters}
	 */
	public void setTextParameters(SignatureImageTextParameters textParameters) {
		this.textParameters = textParameters;
	}

	/**
	 * Returns rotation value for a signature field
	 * @return {@link VisualSignatureRotation}
	 */
	public VisualSignatureRotation getRotation() {
		return rotation;
	}

	/**
	 * Sets a rotation value for the signature field.
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

	/**
	 * Returns a horizontal alignment value of the signature field
	 * @return {@link VisualSignatureAlignmentHorizontal}
	 */
    public SignatureImageParameters.VisualSignatureAlignmentHorizontal getVisualSignatureAlignmentHorizontal() {
        return alignmentHorizontal;
    }

    /**
     * Sets a horizontal alignment respectively to a page of the signature field
     * @param alignmentHorizontal {@link VisualSignatureAlignmentHorizontal}
     */
	public void setAlignmentHorizontal(VisualSignatureAlignmentHorizontal alignmentHorizontal) {
		this.alignmentHorizontal = alignmentHorizontal;
	}

	/**
	 * Returns a vertical alignment value of the signature field
	 * @return {@link VisualSignatureAlignmentVertical}
	 */
    public SignatureImageParameters.VisualSignatureAlignmentVertical getVisualSignatureAlignmentVertical() {
        return alignmentVertical;
    }

    /**
     * Sets a vertical alignment respectively to a page of the signature field
     * @param alignmentVertical {@link VisualSignatureAlignmentVertical}
     */
	public void setAlignmentVertical(VisualSignatureAlignmentVertical alignmentVertical) {
		this.alignmentVertical = alignmentVertical;
	}
}
