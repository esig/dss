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

/**
 * Defines signature field box for a visual PDF signature/timestamp creation
 *
 */
public class RemoteSignatureFieldParameters implements Serializable {

	private static final long serialVersionUID = 1048548792862251941L;

	/** The Id of a field to sign, if present */
	private String fieldId;

	/** The upper left X coordinate */
	private Float originX;
	
	/** The upper left Y coordinate */
	private Float originY;
	
	/** The signature field width */
	private Float width;
	
	/** The signature field height */
	private Float height;

	/** The page number to create the field on */
    private Integer page;

	/**
	 * Default constructor instantiating object with null values
	 */
	public RemoteSignatureFieldParameters() {
	}
	
	/**
	 * Returns the field Id to be signed
	 *
	 * @return {@link String}
	 */
	public String getFieldId() {
		return fieldId;
	}

	/**
	 * Sets the field Id to be signed
	 *
	 * NOTE: to be used only when the field is already exists within a PDF file
	 *
	 * @param fieldId {@link String}
	 */
	public void setFieldId(String fieldId) {
		this.fieldId = fieldId;
	}

	/**
	 * Gets the upper left X coordinate
	 *
	 * @return {@link Float}
	 */
	public Float getOriginX() {
		return originX;
	}

	/**
	 * Sets the upper left X coordinate
	 *
	 * @param originX {@link Float}
	 */
	public void setOriginX(Float originX) {
		this.originX = originX;
	}

	/**
	 * Gets the upper left Y coordinate
	 *
	 * @return {@link Float}
	 */
	public Float getOriginY() {
		return originY;
	}

	/**
	 * Sets the upper left Y coordinate
	 *
	 * @param originY {@link Float}
	 */
	public void setOriginY(Float originY) {
		this.originY = originY;
	}

	/**
	 * Gets the signature field box width
	 *
	 * @return {@link Float}
	 */
	public Float getWidth() {
		return width;
	}

	/**
	 * Sets the signature field box width
	 *
	 * @param width {@link Float}
	 */
	public void setWidth(Float width) {
		this.width = width;
	}

	/**
	 * Gets the signature field box height
	 *
	 * @return {@link Float}
	 */
	public Float getHeight() {
		return height;
	}

	/**
	 * Sets the signature field box height
	 *
	 * @param height {@link Float}
	 */
	public void setHeight(Float height) {
		this.height = height;
	}

	/**
	 * Gets the page number to create the signature on
	 *
	 * @return {@link Integer}
	 */
	public Integer getPage() {
		return page;
	}

	/**
	 * Sets the page number to create the signature on
	 *
	 * @param page {@link Integer}
	 */
	public void setPage(Integer page) {
		this.page = page;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((fieldId == null) ? 0 : fieldId.hashCode());
		result = prime * result + ((height == null) ? 0 : height.hashCode());
		result = prime * result + ((originX == null) ? 0 : originX.hashCode());
		result = prime * result + ((originY == null) ? 0 : originY.hashCode());
		result = prime * result + ((page == null) ? 0 : page.hashCode());
		result = prime * result + ((width == null) ? 0 : width.hashCode());
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
		RemoteSignatureFieldParameters other = (RemoteSignatureFieldParameters) obj;
		if (fieldId == null) {
			if (other.fieldId != null) {
				return false;
			}
		} else if (!fieldId.equals(other.fieldId)) {
			return false;
		}
		if (height == null) {
			if (other.height != null) {
				return false;
			}
		} else if (!height.equals(other.height)) {
			return false;
		}
		if (originX == null) {
			if (other.originX != null) {
				return false;
			}
		} else if (!originX.equals(other.originX)) {
			return false;
		}
		if (originY == null) {
			if (other.originY != null) {
				return false;
			}
		} else if (!originY.equals(other.originY)) {
			return false;
		}
		if (page == null) {
			if (other.page != null) {
				return false;
			}
		} else if (!page.equals(other.page)) {
			return false;
		}
		if (width == null) {
			if (other.width != null) {
				return false;
			}
		} else if (!width.equals(other.width)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "RemoteSignatureFieldParameters [fieldId=" + fieldId + ", originX=" + originX + ", originY=" + originY
				+ ", width=" + width + ", height=" + height + ", page=" + page + "]";
	}

}
