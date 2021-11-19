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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import org.jose4j.jwx.CompactSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * The class is used to parse a Compact JWS
 *
 */
public class JWSCompactSerializationParser {

	private static final Logger LOG = LoggerFactory.getLogger(JWSCompactSerializationParser.class);

	/** Defines the maximum number of '.' character inside a JWS signature */
	private final static int NUMBER_DOTS = 2;

	/** Dot character, used as a separator of parts within a JWS Compact signature */
	private final static byte DOT_CHARACTER = '.';

	/** The document to be parsed */
	private final DSSDocument document;

	/**
	 * The default constructor
	 *
	 * @param document {@link DSSDocument} to parse
	 */
	public JWSCompactSerializationParser(DSSDocument document) {
		this.document = document;
	}

	/**
	 * Parses the provided document and returns a JWS Compact signature if found
	 * 
	 * @return {@link JWS}
	 */
	public JWS parse() {
		try (Scanner scanner = new Scanner(document.openStream(), StandardCharsets.UTF_8.name())) {
			String compactSerialization = scanner.nextLine();
			String[] parts = CompactSerializer.deserialize(compactSerialization);
			return new JWS(parts);
		}
	}
	
	/**
	 * Verifies if the provided file is a Compact JWS
	 * 
	 * @return TRUE if the document is a Compact JWS and supported by the parser, FALSE otherwise
	 */
	public boolean isSupported() {
		if (!DSSJsonUtils.isAllowedSignatureDocumentType(document)) {
			return false;
		}

		int separatorCounter = 0;
		boolean ending = false; // used to detect and "trim" line breaks in the end of JWS string
		try (InputStream is = document.openStream()) {
			int b;
			while ((b = is.read()) != -1) {
				byte currentByte = (byte) b;
				
				if (DSSUtils.isLineBreakByte(currentByte)) {
					ending = true;
				} else if (ending) {
					return false;
				} else if (currentByte == DOT_CHARACTER) {
					 separatorCounter++;
					 if (separatorCounter > NUMBER_DOTS) {
						 return false;
					 }
				} else if (DSSJsonUtils.isBase64UrlEncoded(currentByte)) {
					// continue
				} else if (separatorCounter == 1 && DSSJsonUtils.isUrlSafe(currentByte)) {
					// continue (payload can be not Base64Url encoded)
				} else {
					return false;
				}
			}

			if (separatorCounter != NUMBER_DOTS) {
				return false;
			}

		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read the document. Reason : %s", e.getMessage()), e);
		}
		if (ending) {
			LOG.warn("Line break characters found within the JWS Compact Serialization signature document!");
		}
		return true;
	}

}
