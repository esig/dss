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
	/* Allows to send only the digest of the document */
	private DigestAlgorithm digestAlgorithm;
	private String name = "RemoteDocument";
	private MimeType mimeType;

	public RemoteDocument() {
	}

	/**
	 * This constructor allows to create a new instance of RemoteDocument with the whole document
	 * 
	 * @param bytes
	 *            the full document binaries
	 * @param mimeType
	 *            the mimetype
	 * @param name
	 *            the document name
	 */
	public RemoteDocument(byte[] bytes, MimeType mimeType, String name) {
		this.bytes = bytes;
		this.mimeType = mimeType;
		this.name = name;
	}

	/**
	 * This constructor allows to create an instance of RemoteDocument with a digest document
	 * 
	 * @param bytes
	 *            the result of the digest
	 * @param digestAlgorithm
	 *            the used digest algorithm
	 * @param mimeType
	 *            the mimetype
	 * @param name
	 *            the document name
	 */
	public RemoteDocument(byte[] bytes, DigestAlgorithm digestAlgorithm, MimeType mimeType, String name) {
		this.bytes = bytes;
		this.digestAlgorithm = digestAlgorithm;
		this.mimeType = mimeType;
		this.name = name;
	}

	/**
	 * Returns the array of bytes representing the document or its digest value.
	 *
	 * @return array of {@code byte}
	 */
	public byte[] getBytes() {
		return bytes;
	}

	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	/**
	 * Returns the current used digest algorithm
	 * 
	 * @return
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
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
		result = prime * result + Arrays.hashCode(bytes);
		result = prime * result + ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
		result = prime * result + ((mimeType == null) ? 0 : mimeType.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RemoteDocument other = (RemoteDocument) obj;
		if (!Arrays.equals(bytes, other.bytes))
			return false;
		if (digestAlgorithm != other.digestAlgorithm)
			return false;
		if (mimeType == null) {
			if (other.mimeType != null)
				return false;
		} else if (!mimeType.equals(other.mimeType))
			return false;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "RemoteDocument [bytes=" + Arrays.toString(bytes) + ", digestAlgorithm=" + digestAlgorithm + ", name=" + name + ", mimeType=" + mimeType + "]";
	}

}
