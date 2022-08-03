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
package eu.europa.esig.dss.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;

/**
 * This class allows handling of different mime types. It also allows addition of a new mime-type.
 *
 */
@SuppressWarnings("serial")
public class MimeType implements Serializable {

	private static final Logger LOG = LoggerFactory.getLogger(MimeType.class);

	/** Map of registered MimeTypes */
	private static Map<String, MimeType> mimeTypes = new HashMap<>();

	/** Map of registered MimeType names and corresponding file extensions */
	private static Map<String, MimeType> fileExtensions = new HashMap<>();

	/** octet-stream */
	public static final MimeType BINARY = new MimeType("application/octet-stream");
	/** xml */
	public static final MimeType XML = new MimeType("text/xml");
	/** html */
	public static final MimeType HTML = new MimeType("text/html");
	/** pdf */
	public static final MimeType PDF = new MimeType("application/pdf");
	/** pkcs7-signature */
	public static final MimeType PKCS7 = new MimeType("application/pkcs7-signature");
	/** json */
	public static final MimeType JSON = new MimeType("application/json");
	/** jose */
	public static final MimeType JOSE = new MimeType("application/jose");
	/** jose+json */
	public static final MimeType JOSE_JSON = new MimeType("application/jose+json");
	/** timestamp-token */
	public static final MimeType TST = new MimeType("application/vnd.etsi.timestamp-token");
	/** zip */
	public static final MimeType ZIP = new MimeType("application/zip");
	/** asic-s */
	public static final MimeType ASICS = new MimeType("application/vnd.etsi.asic-s+zip");
	/** asic-e */
	public static final MimeType ASICE = new MimeType("application/vnd.etsi.asic-e+zip");
	/** opendocument text */
	public static final MimeType ODT = new MimeType("application/vnd.oasis.opendocument.text");
	/** opendocument spreadsheet */
	public static final MimeType ODS = new MimeType("application/vnd.oasis.opendocument.spreadsheet");
	/** opendocument presentation */
	public static final MimeType ODP = new MimeType("application/vnd.oasis.opendocument.presentation");
	/** opendocument graphics */
	public static final MimeType ODG = new MimeType("application/vnd.oasis.opendocument.graphics");
	/** plain text */
	public static final MimeType TEXT = new MimeType("text/plain");
	/** crl */
	public static final MimeType CRL = new MimeType("application/pkix-crl");
	/** certificate */
	public static final MimeType CER = new MimeType("application/pkix-cert");

	/** png */
	public static final MimeType PNG = new MimeType("image/png");
	/** jpeg */
	public static final MimeType JPEG = new MimeType("image/jpeg");
	/** svg */
	public static final MimeType SVG = new MimeType("image/svg+xml");

	/** The MimeType string */
	private String mimeTypeString;

	static {
		fileExtensions.put("xml", XML);
		fileExtensions.put("html", HTML);

		fileExtensions.put("pkcs7", PKCS7);
		fileExtensions.put("p7m", PKCS7);
		fileExtensions.put("p7s", PKCS7);

		fileExtensions.put("pdf", PDF);

		fileExtensions.put("json", JSON);

		fileExtensions.put("zip", ZIP);

		fileExtensions.put("asics", ASICS);
		fileExtensions.put("scs", ASICS);

		fileExtensions.put("asice", ASICE);
		fileExtensions.put("sce", ASICE);
		// estonian bdoc file type is handled as asic-e document
		fileExtensions.put("bdoc", ASICE);

		// ASiC-E open-document
		fileExtensions.put("odt", ODT);
		fileExtensions.put("ods", ODS);
		fileExtensions.put("odp", ODP);
		fileExtensions.put("odg", ODG);

		fileExtensions.put("txt", TEXT);

		fileExtensions.put("png", PNG);
		fileExtensions.put("jpg", JPEG);
		fileExtensions.put("jpeg", JPEG);
		fileExtensions.put("svg", SVG);

		fileExtensions.put("tst", TST);
	}

	/**
	 * This constructor is used only by the web-services.
	 */
	public MimeType() {
		// empty
	}

	/**
	 * The default constructor for MimeType.
	 *
	 * @param mimeTypeString
	 *            is a string identifier composed of two parts: a "type" and a
	 *            "subtype"
	 */
	private MimeType(final String mimeTypeString) {
		Objects.requireNonNull(mimeTypeString, "The mimeTypeString cannot be null!");

		if (!mimeTypeString.matches("([\\w])*/([\\w\\-\\+\\.])*")) {
			LOG.warn("'{}' is not conformant mime-type string! (see RFC 2045)", mimeTypeString);
		}
		if (mimeTypes.get(mimeTypeString) != null) {
			throw new DSSException(String.format("'%s' corresponding MimeType exists already! " +
					"Use #fromMimeTypeString method to obtain the corresponding object.", mimeTypeString));
		}
		this.mimeTypeString = mimeTypeString;
		mimeTypes.put(mimeTypeString, this);
	}

	/**
	 * This constructor allows to create a new MimeType related to given file
	 * extension. Be careful, if the file extension has already an associated
	 * {@code MimeType} then this relation will be lost.
	 *
	 * @param mimeTypeString
	 *            is a string identifier composed of two parts: a "type" and a
	 *            "subtype"
	 * @param extension
	 *            to be defined. Example: "txt", note that there is no point
	 *            before the extension name.
	 */
	public MimeType(final String mimeTypeString, final String extension) {
		this(mimeTypeString);
		defineFileExtension(extension);
	}

	/**
	 * Gets String identifying the MimeType
	 *
	 * @return the mimeTypeString
	 */
	public String getMimeTypeString() {
		return mimeTypeString;
	}

	/**
	 * This setter is used by the web-services.
	 *
	 * @param mimeTypeString
	 *            is a string identifier composed of two parts: a "type" and a
	 *            "subtype"
	 */
	public void setMimeTypeString(String mimeTypeString) {
		this.mimeTypeString = mimeTypeString;
	}

	/**
	 * This method returns the mime-type extrapolated from the file name.
	 *
	 * @param fileName
	 *            the file name to be analysed
	 * @return the extrapolated mime-type of the file name
	 */
	public static MimeType fromFileName(final String fileName) {
		final String fileExtension = getFileExtension(fileName);
		if (fileExtension != null) {
			final String lowerCaseExtension = fileExtension.toLowerCase();
			final MimeType mimeType = fileExtensions.get(lowerCaseExtension);
			if (mimeType != null) {
				return mimeType;
			}
		}
		return BINARY;
	}

	/**
	 * Returns the file exception for the provided MimeType
	 * 
	 * @param mimeType 
	 * 			  {@link MimeType} to get an extension for
	 * @return the exception {@link String} assigned to the given MimeType
	 * @throws DSSException in case if the extension for the requested MimeType is not found
	 */
	public static String getExtension(MimeType mimeType) {
		Objects.requireNonNull(mimeType, "The MimeType must be provided!");
		for (Entry<String, MimeType> entry : fileExtensions.entrySet()) {
			if (mimeType.equals(entry.getValue())) {
				return entry.getKey();
			}
		}
		LOG.warn("The MimeType '{}' is not known or does not have a particular extension", mimeType);
		return null;
	}

	/**
	 * Returns the file extension based on the position of the '.' in the fileName.
	 * File paths as "xxx.y/toto" are not handled.
	 *
	 * @param fileName
	 *            to be analysed
	 * @return the file extension or null
	 */
	public static String getFileExtension(final String fileName) {
		if (fileName == null || fileName.trim().length() == 0) {
			return null;
		}

		String extension = "";
		int lastIndexOf = fileName.lastIndexOf('.');
		if (lastIndexOf > 0) {
			extension = fileName.substring(lastIndexOf + 1);
		}
		return extension;
	}

	/**
	 * This method returns the mime-type extrapolated from the file.
	 *
	 * @param file
	 *            the file to be analysed
	 * @return the extrapolated mime-type of the file
	 */
	public static MimeType fromFile(final File file) {
		Objects.requireNonNull(file, "The file cannot be null!");
		
		final String fileName = file.getName();
		return fromFileName(fileName);
	}

	/**
	 * This method returns the first representation of the {@code MimeType}
	 * corresponding to the given mime-type string.
	 *
	 * @param mimeTypeString
	 *            is a string identifier composed of two parts: a "type" and a
	 *            "subtype"
	 * @return the extrapolated mime-type from the {@code String}
	 */
	public static MimeType fromMimeTypeString(final String mimeTypeString) {
		Objects.requireNonNull(mimeTypeString, "The mimeTypeString cannot be null!");

		MimeType mimeType = mimeTypes.get(mimeTypeString);
		if (mimeType == null) {
			mimeType = new MimeType(mimeTypeString);
		}
		return mimeType;
	}

	/**
	 * This method allows to define a new relationship between a file extension
	 * and a {@code MimeType}.
	 *
	 * @param extension
	 *            to be defined. Example: "txt", note that there is no point
	 *            before the extension name.
	 */
	public void defineFileExtension(final String extension) {
		if (extension == null || extension.trim().length() == 0) {
			throw new IllegalArgumentException("The extension cannot be null or blank!");
		}
		fileExtensions.put(extension, this);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((mimeTypeString == null) ? 0 : mimeTypeString.hashCode());
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
		MimeType other = (MimeType) obj;
		if (mimeTypeString == null) {
			if (other.mimeTypeString != null) {
				return false;
			}
		} else if (!mimeTypeString.equals(other.mimeTypeString)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "MimeType [mimeTypeString=" + mimeTypeString + "]";
	}

}
