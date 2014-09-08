/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
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

/**
 * TODO
 * <p/>
 * <p> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision$ - $Date$
 */
public enum MimeType {

	BINARY("application/octet-stream"), XML("text/xml"), PDF("application/pdf"), PKCS7("application/pkcs7-signature"), ASICS("application/vnd.etsi.asic-s+zip"), ASICE(
		  "application/vnd.etsi.asic-e+zip"), TEXT("text/plain");

	private String code;

	private static Map<String, MimeType> fileExtensions = new HashMap<String, MimeType>() {{
		put("xml", XML);
		put("pdf", PDF);
		put("asics", ASICS);
		put("scs", ASICS);
		put("asice", ASICE);
		put("sce", ASICE);
		put("txt", TEXT);
	}};

	/**
	 * The default constructor for MimeTypes.
	 */
	private MimeType(final String code) {
		this.code = code;
	}

	/**
	 * @return the code
	 */
	public String getCode() {
		return code;
	}

	public static MimeType fromFileName(final String name) {

		final String inLowerCaseName = name.toLowerCase();
		final String fileExtension = DSSUtils.getFileExtension(inLowerCaseName);
		final MimeType mimeType = fileExtensions.get(fileExtension);
		if (mimeType != null) {
			return mimeType;
		}
		return BINARY;
	}

	/**
	 * This method returns the mime-type extrapolated from the file name. In case of a zip container its content is analysed to determinate if it is an ASiC signature.
	 *
	 * @param file the file to be analysed
	 * @return the extrapolated mime-type of the file
	 */
	public static MimeType fromFile(final File file) {

		final String fileName = file.getName();
		final MimeType mimeType = fromFileName(fileName);
		return mimeType;
	}

	public static MimeType fromCode(final String mimeTypeString) {

		for (final MimeType mimeType : values()) {

			if (mimeType.code.equals(mimeTypeString)) {
				return mimeType;
			}
		}
		return null;
	}

	/**
	 * This method allows to define a new relationship between a file extension and a {@code MimeType}.
	 *
	 * @param extension to be defined. Example: "txt", note that there is no point before the extension name.
	 */
	public void defineFileExtension(final String extension) {

		fileExtensions.put(extension, this);
	}
}
