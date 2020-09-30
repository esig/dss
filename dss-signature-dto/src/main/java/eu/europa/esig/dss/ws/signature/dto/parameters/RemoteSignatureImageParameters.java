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
package eu.europa.esig.dss.ws.signature.dto.parameters;

import java.io.Serializable;

import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.ws.dto.RemoteColor;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

@SuppressWarnings("serial")
public class RemoteSignatureImageParameters implements Serializable {

	private VisualSignatureAlignmentHorizontal alignmentHorizontal;

	private VisualSignatureAlignmentVertical alignmentVertical;

	private RemoteColor backgroundColor;

    private Integer dpi;

    private RemoteDocument image;

	private VisualSignatureRotation rotation;
	
	private RemoteSignatureFieldParameters fieldParameters;

    private RemoteSignatureImageTextParameters textParameters;

    private Integer zoom;

	public VisualSignatureAlignmentHorizontal getAlignmentHorizontal() {
        return this.alignmentHorizontal;
    }

	public void setAlignmentHorizontal(final VisualSignatureAlignmentHorizontal alignmentHorizontal) {
        this.alignmentHorizontal = alignmentHorizontal;
    }

	public VisualSignatureAlignmentVertical getAlignmentVertical() {
        return this.alignmentVertical;
    }

	public void setAlignmentVertical(final VisualSignatureAlignmentVertical alignmentVertical) {
        this.alignmentVertical = alignmentVertical;
    }

	public RemoteColor getBackgroundColor() {
        return this.backgroundColor;
    }

	public void setBackgroundColor(final RemoteColor backgroundColor) {
        this.backgroundColor = backgroundColor;
    }

    public Integer getDpi() {
        return this.dpi;
    }

    public void setDpi(final Integer dpi) {
        this.dpi = dpi;
    }

    public RemoteDocument getImage() {
        return this.image;
    }

    public void setImage(final RemoteDocument image) {
        this.image = image;
    }

	public RemoteSignatureFieldParameters getFieldParameters() {
		return fieldParameters;
	}

	public void setFieldParameters(RemoteSignatureFieldParameters fieldParameters) {
		this.fieldParameters = fieldParameters;
	}

    public RemoteSignatureImageTextParameters getTextParameters() {
        return this.textParameters;
    }

    public void setTextParameters(final RemoteSignatureImageTextParameters textParameters) {
        this.textParameters = textParameters;
    }

	public VisualSignatureRotation getRotation() {
        return this.rotation;
    }

	public void setRotation(final VisualSignatureRotation rotation) {
        this.rotation = rotation;
    }

    public Integer getZoom() {
        return this.zoom;
    }

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
		result = prime * result + ((rotation == null) ? 0 : rotation.hashCode());
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
		if (rotation != other.rotation) {
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
				+ ", rotation=" + rotation + ", fieldParameters=" + fieldParameters + ", textParameters="
				+ textParameters + ", zoom=" + zoom + "]";
	}

}
