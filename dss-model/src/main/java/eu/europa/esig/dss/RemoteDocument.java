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
package eu.europa.esig.dss;

import java.io.Serializable;
import java.util.Arrays;

/**
 * This class is used to transport a DSSDocument with SOAP and/or REST
 */
@SuppressWarnings("serial")
public class RemoteDocument implements Serializable {

	private byte[] bytes;
	private String name = "RemoteDocument";
	private String absolutePath = "RemoteDocument";
	private MimeType mimeType;

	public RemoteDocument() {
	}

	public RemoteDocument(byte[] bytes, MimeType mimeType, String name) {
		this.bytes = bytes;
		this.mimeType = mimeType;
		this.name = name;
	}

	public RemoteDocument(byte[] bytes, MimeType mimeType, String name, String absolutePath) {
		this.bytes = bytes;
		this.mimeType = mimeType;
		this.name = name;
		this.absolutePath = absolutePath;
	}

	/**
	 * Returns the array of bytes representing the document. Do not use this method with large files.
	 *
	 * @return array of {@code byte}
	 */
	public byte[] getBytes() {
		return bytes;
	}

	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getAbsolutePath() {
		return absolutePath;
	}

	public void setAbsolutePath(String absolutePath) {
		this.absolutePath = absolutePath;
	}

	public MimeType getMimeType() {
		return mimeType;
	}

	public void setMimeType(MimeType mimeType) {
		this.mimeType = mimeType;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((absolutePath == null) ? 0 : absolutePath.hashCode());
		result = (prime * result) + Arrays.hashCode(bytes);
		result = (prime * result) + ((mimeType == null) ? 0 : mimeType.hashCode());
		result = (prime * result) + ((name == null) ? 0 : name.hashCode());
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
		RemoteDocument other = (RemoteDocument) obj;
		if (absolutePath == null) {
			if (other.absolutePath != null) {
				return false;
			}
		} else if (!absolutePath.equals(other.absolutePath)) {
			return false;
		}
		if (!Arrays.equals(bytes, other.bytes)) {
			return false;
		}
		if (mimeType == null) {
			if (other.mimeType != null) {
				return false;
			}
		} else if (!mimeType.equals(other.mimeType)) {
			return false;
		}
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		} else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "RemoteDocument [bytes=" + Arrays.toString(bytes) + ", name=" + name + ", absolutePath=" + absolutePath + ", mimeType=" + mimeType + "]";
	}

}
