/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT),
 * B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL$
 * $Revision$
 * $Date$
 * $Author$
 */
package eu.europa.ec.markt.dss.signature;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * This class allows to handle different mime types. It also allows to add (define) new mime-type.
 * <p/>
 * <p> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision$ - $Date$
 */
public class MimeType {

	private static Map<String, MimeType> mimeTypes = new HashMap<String, MimeType>();

	public static final MimeType BINARY = new MimeType("application/octet-stream");
	public static final MimeType XML = new MimeType("text/xml");
	public static final MimeType PDF = new MimeType("application/pdf");
	public static final MimeType PKCS7 = new MimeType("application/pkcs7-signature");
	public static final MimeType ASICS = new MimeType("application/vnd.etsi.asic-s+zip");
	public static final MimeType ASICE = new MimeType("application/vnd.etsi.asic-e+zip");
	public static final MimeType TEXT = new MimeType("text/plain");

	private String mimeTypeString;

	private static Map<String, MimeType> fileExtensions = new HashMap<String, MimeType>() {{

		put("xml", XML);
		put("pdf", PDF);
		put("asics", ASICS);
		put("scs", ASICS);
		put("asice", ASICE);
		put("bdoc", ASICE); // estonian bdoc file type is handled as asic-e document
		put("sce", ASICE);
		put("txt", TEXT);
	}};

	/**
	 * The default constructor for MimeType.
	 *
	 * @param mimeTypeString is a string identifier composed of two parts: a "type" and a "subtype"
	 */
	private MimeType(final String mimeTypeString) {

		if (!mimeTypeString.matches("([\\w])*/([\\w\\-\\+\\.])*")) {
			throw new DSSException("'" + mimeTypeString + "' is not conformant mime-type string!");
		}
		if (mimeTypes.get(mimeTypeString) != null) {
			throw new DSSException("'" + mimeTypeString + "' corresponding MimeType exists already! Use #fromMimeTypeString method to obtain the corresponding object.");
		}
		this.mimeTypeString = mimeTypeString;
		mimeTypes.put(mimeTypeString, this);
	}

	/**
	 * This constructor allows to create a new MimeType related to given file extension. Be careful, if the file extension has already an associated {@code MimeType} then this
	 * relation will be lost.
	 *
	 * @param mimeTypeString is a string identifier composed of two parts: a "type" and a "subtype"
	 * @param extension      to be defined. Example: "txt", note that there is no point before the extension name.
	 */
	public MimeType(final String mimeTypeString, final String extension) {

		this(mimeTypeString);
		fileExtensions.put(extension, this);
	}

	/**
	 * @return the mimeTypeString
	 */
	public String getCode() {
		return mimeTypeString;
	}

	/**
	 * This method returns the internal name of the mime-type
	 *
	 * @return
	 */
	public String name() {
		return this.name();
	}

	/**
	 * This method returns the mime-type extrapolated from the file name.
	 *
	 * @param fileName the file name to be analysed
	 * @return the extrapolated mime-type of the file name
	 */
	public static MimeType fromFileName(final String fileName) {

		final String inLowerCaseName = fileName.toLowerCase();
		final String fileExtension = DSSUtils.getFileExtension(inLowerCaseName);
		final MimeType mimeType = fileExtensions.get(fileExtension);
		if (mimeType != null) {
			return mimeType;
		}
		return BINARY;
	}

	/**
	 * This method returns the mime-type extrapolated from the file.
	 *
	 * @param file the file to be analysed
	 * @return the extrapolated mime-type of the file
	 */
	public static MimeType fromFile(final File file) {

		final String fileName = file.getName();
		final MimeType mimeType = fromFileName(fileName);
		return mimeType;
	}

	/**
	 * This method returns the first representation of the {@code MimeType} corresponding to the given mime-type string.
	 *
	 * @param mimeTypeString is a string identifier composed of two parts: a "type" and a "subtype"
	 * @return the extrapolated mime-type from the {@code String}
	 */
	public static MimeType fromMimeTypeString(final String mimeTypeString) {

		MimeType mimeType = mimeTypes.get(mimeTypeString);
		if (mimeType == null) {
			mimeType = new MimeType(mimeTypeString);
		}
		return mimeType;
	}

	/**
	 * This method allows to define a new relationship between a file extension and a {@code MimeType}.
	 *
	 * @param extension to be defined. Example: "txt", note that there is no point before the extension name.
	 */
	public void defineFileExtension(final String extension) {
		fileExtensions.put(extension, this);
	}

	@Override
	public boolean equals(Object obj) {

		return obj instanceof MimeType && mimeTypeString.equals(((MimeType) obj).mimeTypeString);
	}
}
