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

import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.visible.DPIUtils;

import java.awt.*;
import java.io.Serializable;

/**
 * Parameters for a visible signature creation
 *
 */
public class SignatureImageParameters implements Serializable {

	private static final long serialVersionUID = -327971057134928889L;

	/** The default zoom constraint */
	private static final int NO_SCALING = 100;

	/**
	 * This variable contains the image to use (company logo,...)
	 */
	private DSSDocument image;
	
	/**
	 * This variable defines a {@code SignatureFieldParameters} like field positions and dimensions
	 */
	private SignatureFieldParameters fieldParameters;
        
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
	 * Returns {@code SignatureFieldParameters}
	 * 
	 * @return {@link SignatureFieldParameters}
	 */
	public SignatureFieldParameters getFieldParameters() {
		if (fieldParameters == null) {
			fieldParameters = new SignatureFieldParameters();
		}
		return fieldParameters;
	}
	
	/**
	 * Sets {@code SignatureFieldParameters}, like signature field position and dimensions
	 * 
	 * @param fieldParameters {@link SignatureFieldParameters}
	 */
	public void setFieldParameters(SignatureFieldParameters fieldParameters) {
		this.fieldParameters = fieldParameters;
	}

	/**
	 * Allows specifying of an absolute margin for the signature field by X axis
	 * 
	 * Deprecated. Use {@code getFieldParameters().setOriginX(originX)} method
	 * 
	 * @param originX {@code float} margin
	 */
	@Deprecated
	public void setxAxis(float originX) {
		getFieldParameters().setOriginX(originX);
	}

	/**
	 * Allows specifying of an absolute margin for the signature field by Y axis
	 * 
	 * Deprecated. Use {@code getFieldParameters().setOriginY(originY)} method
	 * 
	 * @param originY {@code float} margin
	 */
	@Deprecated
	public void setyAxis(float originY) {
		getFieldParameters().setOriginY(originY);
	}

	/**
	 * Defines a number of page in the document where the signature field must be placed.
	 * The counting of pages starts from 1 (the first page) (default value = 1)
	 * NOTE: the page must exist in the document!
	 * 
	 * Deprecated. Use {@code getFieldParameters().setPage(page)} method
	 * 
	 * @param page {@code int} page number
	 */
	@Deprecated
	public void setPage(int page) {
		getFieldParameters().setPage(page);
	}

    /**
     * Defines a custom width for the signature field in pixels
	 * 
	 * Deprecated. Use {@code getFieldParameters().setWidth(width)} method
	 * 
     * @param width {@code int} width value
     */
	@Deprecated
    public void setWidth(int width) {
		getFieldParameters().setWidth(width);
    }

    /**
     * Defines a custom height for the signature field in pixels
	 * 
	 * Deprecated. Use {@code getFieldParameters().setHeight(height)} method
	 * 
     * @param height {@code int} height value
     */
	@Deprecated
    public void setHeight(int height) {
		getFieldParameters().setHeight(height);
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
		return DPIUtils.getDpi(dpi);
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
		if (textParameters == null) {
			textParameters = new SignatureImageTextParameters();
		}
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
	public VisualSignatureAlignmentHorizontal getVisualSignatureAlignmentHorizontal() {
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
	public VisualSignatureAlignmentVertical getVisualSignatureAlignmentVertical() {
        return alignmentVertical;
    }

    /**
     * Sets a vertical alignment respectively to a page of the signature field
     * @param alignmentVertical {@link VisualSignatureAlignmentVertical}
     */
	public void setAlignmentVertical(VisualSignatureAlignmentVertical alignmentVertical) {
		this.alignmentVertical = alignmentVertical;
	}
	
	/**
	 * Checks if the {@code SignatureImageParameters} is empty (no image or text parameters are defined)
	 * 
	 * @return TRUE if the parameters are empty, FALSE otherwise
	 */
	public boolean isEmpty() {
		return image == null && getTextParameters().isEmpty();
	}

	@Override
	public String toString() {
		return "SignatureImageParameters [image=" + image + ", zoom=" + zoom
				+ ", backgroundColor=" + backgroundColor + ", dpi=" + dpi + ", rotation=" + rotation
				+ ", alignmentHorizontal=" + alignmentHorizontal + ", alignmentVertical=" + alignmentVertical
				+ ", fieldParameters=" + getFieldParameters() + ", textParameters=" + getTextParameters() + "]";
	}
	
}
