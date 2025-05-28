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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.enumerations.ASiCContainerType;

import java.io.Serializable;
import java.util.Objects;

/**
 * This class regroups the signature parameters related to ASiC form.
 *
 */
@SuppressWarnings("serial")
public class ASiCParameters implements Serializable {

	/**
	 * Indicates if the ZIP comment should be used to store the signed content mime-type.
	 */
	private boolean zipComment = false;

	/**
	 * Indicates the mime-type to be set within the mimetype file. If null the stored mime-type is that of the signed
	 * content.
	 */
	private String mimeType = null;

	/**
	 * The form of the container -S or -E.
	 */
	private ASiCContainerType containerType;

	/**
	 * Default constructor instantiating object with null values
	 */
	public ASiCParameters() {
		// empty
	}

	/**
	 * Indicates if the ZIP comment must include the mime-type.
	 *
	 * @return {@code boolean}
	 */
	public boolean isZipComment() {
		return zipComment;
	}

	/**
	 * This method sets if the zip comment will contain the mime type.
	 *
	 * @param zipComment
	 *            true if a zip comment needs to be added
	 */
	public void setZipComment(final boolean zipComment) {
		this.zipComment = zipComment;
	}

	/**
	 * Gets the mimetype
	 *
	 * @return {@link String} mimetype
	 */
	public String getMimeType() {
		return mimeType;
	}

	/**
	 * This method allows to set the mime-type within the mimetype file.
	 *
	 * @param mimeType
	 *            the mimetype to store
	 */
	public void setMimeType(final String mimeType) {
		this.mimeType = mimeType;
	}

	/**
	 * The method returns the expected type of the ASiC container
	 * 
	 * @return the {@code ASiCContainerType} of the ASiC container
	 */
	public ASiCContainerType getContainerType() {
		return containerType;
	}

	/**
	 * Sets the expected container type
	 *
	 * @param containerType {@link ASiCContainerType}
	 */
	public void setContainerType(ASiCContainerType containerType) {
		this.containerType = containerType;
	}

	@Override
	public String toString() {
		return "ASiCParameters [" +
				"zipComment=" + zipComment +
				", mimeType='" + mimeType + '\'' +
				", containerType=" + containerType +
				']';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		ASiCParameters that = (ASiCParameters) o;
		return zipComment == that.zipComment
				&& Objects.equals(mimeType, that.mimeType)
				&& containerType == that.containerType;
	}

	@Override
	public int hashCode() {
		int result = Boolean.hashCode(zipComment);
		result = 31 * result + Objects.hashCode(mimeType);
		result = 31 * result + Objects.hashCode(containerType);
		return result;
	}

}
