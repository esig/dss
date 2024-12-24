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
package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.ws.dto.RemoteColor;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.io.Serializable;

/**
 * The parameters to be used for a PDF visual signature creation
 *
 */
@SuppressWarnings("serial")
public class RemoteSignatureImageParameters implements Serializable {

	/** Visual signature horizontal position on the pdf page */
	private VisualSignatureAlignmentHorizontal alignmentHorizontal;

	/** Visual signature vertical position on the pdf page */
	private VisualSignatureAlignmentVertical alignmentVertical;

	/** Defines the image scaling behavior within a signature field with a fixed size */
	private ImageScaling imageScaling;

	/** The signature field's background color */
	private RemoteColor backgroundColor;

	/** The signature image DPIs */
    private Integer dpi;

    /** The visual signature image document */
    private RemoteDocument image;

	/** The signature field parameters */
	private RemoteSignatureFieldParameters fieldParameters;

	/** The signature field text parameters */
    private RemoteSignatureImageTextParameters textParameters;

    /** The visual signature zoom */
    private Integer zoom;

	/**
	 * Default constructor instantiating object with null values
	 */
	public RemoteSignatureImageParameters() {
		// empty
	}

	/**
	 * Gets the signature field horizontal alignment on the page
	 *
	 * @return {@link VisualSignatureAlignmentHorizontal}
	 */
	public VisualSignatureAlignmentHorizontal getAlignmentHorizontal() {
        return this.alignmentHorizontal;
    }

	/**
	 * Sets the signature field horizontal alignment on the page
	 *
	 * @param alignmentHorizontal {@link VisualSignatureAlignmentHorizontal}
	 */
	public void setAlignmentHorizontal(final VisualSignatureAlignmentHorizontal alignmentHorizontal) {
        this.alignmentHorizontal = alignmentHorizontal;
    }

	/**
	 * Gets the signature field vertical alignment on the page
	 *
	 * @return {@link VisualSignatureAlignmentHorizontal}
	 */
	public VisualSignatureAlignmentVertical getAlignmentVertical() {
        return this.alignmentVertical;
    }

	/**
	 * Sets the signature field vertical alignment on the page
	 *
	 * @param alignmentVertical {@link VisualSignatureAlignmentVertical}
	 */
	public void setAlignmentVertical(final VisualSignatureAlignmentVertical alignmentVertical) {
        this.alignmentVertical = alignmentVertical;
    }

	/**
	 * Gets the image scaling
	 *
	 * @return {@link ImageScaling}
	 */
	public ImageScaling getImageScaling() {
		return imageScaling;
	}

	/**
	 * Sets the image scaling behavior for a signature field with a fixed size
	 *
	 * @param imageScaling {@link ImageScaling}
	 */
	public void setImageScaling(ImageScaling imageScaling) {
		this.imageScaling = imageScaling;
	}

	/**
	 * Gets the signature field background color
	 *
	 * @return {@link RemoteColor}
	 */
	public RemoteColor getBackgroundColor() {
        return this.backgroundColor;
    }

	/**
	 * Sets the signature field background color
	 *
	 * @param backgroundColor {@link RemoteColor}
	 */
	public void setBackgroundColor(final RemoteColor backgroundColor) {
        this.backgroundColor = backgroundColor;
    }

	/**
	 * Gets the image dpi
	 *
	 * @return {@link Integer}
	 */
	public Integer getDpi() {
        return this.dpi;
    }

	/**
	 * Sets the image dpi
	 *
	 * @param dpi {@link Integer}
	 */
	public void setDpi(final Integer dpi) {
        this.dpi = dpi;
    }

	/**
	 * Gets the image document
	 *
	 * @return {@link RemoteDocument}
	 */
	public RemoteDocument getImage() {
        return this.image;
    }

	/**
	 * Sets the image document
	 *
	 * @param image {@link RemoteDocument}
	 */
	public void setImage(final RemoteDocument image) {
        this.image = image;
    }

	/**
	 * Gets the visual signature field parameters
	 *
	 * @return {@link RemoteSignatureFieldParameters}
	 */
	public RemoteSignatureFieldParameters getFieldParameters() {
		return fieldParameters;
	}

	/**
	 * Sets the visual signature field parameters
	 *
	 * @param fieldParameters {@link RemoteSignatureFieldParameters}
	 */
	public void setFieldParameters(RemoteSignatureFieldParameters fieldParameters) {
		this.fieldParameters = fieldParameters;
	}

	/**
	 * Gets the text parameters
	 *
	 * @return {@link RemoteSignatureImageTextParameters}
	 */
    public RemoteSignatureImageTextParameters getTextParameters() {
        return this.textParameters;
    }

	/**
	 * Sets the text parameters
	 *
	 * @param textParameters {@link RemoteSignatureImageTextParameters}
	 */
	public void setTextParameters(final RemoteSignatureImageTextParameters textParameters) {
        this.textParameters = textParameters;
    }

	/**
	 * Gets signature field zoom
	 *
	 * @return {@link Integer}
	 */
	public Integer getZoom() {
        return this.zoom;
    }

	/**
	 * Sets the signature field zoom
	 *
	 * @param zoom {@link Integer}
	 */
	public void setZoom(final Integer zoom) {
        this.zoom = zoom;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((alignmentHorizontal == null) ? 0 : alignmentHorizontal.hashCode());
		result = prime * result + ((alignmentVertical == null) ? 0 : alignmentVertical.hashCode());
		result = prime * result + ((backgroundColor == null) ? 0 : backgroundColor.hashCode());
		result = prime * result + ((dpi == null) ? 0 : dpi.hashCode());
		result = prime * result + ((fieldParameters == null) ? 0 : fieldParameters.hashCode());
		result = prime * result + ((image == null) ? 0 : image.hashCode());
		result = prime * result + ((textParameters == null) ? 0 : textParameters.hashCode());
		result = prime * result + ((zoom == null) ? 0 : zoom.hashCode());
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
		RemoteSignatureImageParameters other = (RemoteSignatureImageParameters) obj;
		if (alignmentHorizontal != other.alignmentHorizontal) {
			return false;
		}
		if (alignmentVertical != other.alignmentVertical) {
			return false;
		}
		if (backgroundColor == null) {
			if (other.backgroundColor != null) {
				return false;
			}
		} else if (!backgroundColor.equals(other.backgroundColor)) {
			return false;
		}
		if (dpi == null) {
			if (other.dpi != null) {
				return false;
			}
		} else if (!dpi.equals(other.dpi)) {
			return false;
		}
		if (fieldParameters == null) {
			if (other.fieldParameters != null) {
				return false;
			}
		} else if (!fieldParameters.equals(other.fieldParameters)) {
			return false;
		}
		if (image == null) {
			if (other.image != null) {
				return false;
			}
		} else if (!image.equals(other.image)) {
			return false;
		}
		if (textParameters == null) {
			if (other.textParameters != null) {
				return false;
			}
		} else if (!textParameters.equals(other.textParameters)) {
			return false;
		}
		if (zoom == null) {
			if (other.zoom != null) {
				return false;
			}
		} else if (!zoom.equals(other.zoom)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "RemoteSignatureImageParameters [alignmentHorizontal=" + alignmentHorizontal + ", alignmentVertical="
				+ alignmentVertical + ", backgroundColor=" + backgroundColor + ", dpi=" + dpi + ", image=" + image
				 + ", fieldParameters=" + fieldParameters + ", textParameters="
				+ textParameters + ", zoom=" + zoom + "]";
	}

}
