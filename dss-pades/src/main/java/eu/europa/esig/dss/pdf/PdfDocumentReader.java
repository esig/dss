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
package eu.europa.esig.dss.pdf;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public interface PdfDocumentReader extends Closeable {
	
	/**
	 * Loads the last DSS dictionary from the document if exists
	 * NOTE: can return null if DSS dictionary is not present
	 * 
	 * @return {@link PdfDssDict}
	 */
	PdfDssDict getDSSDictionary();
	
	/**
	 * Extracts PdfSignatureSictionaries present in the signature
	 * 
	 * @return a map between {@link PdfSignatureDictionary} and related field names
	 * @throws IOException if an exception occurs
	 */
	Map<PdfSignatureDictionary, List<String>> extractSigDictionaries() throws IOException;
	
	/**
	 * Checks if a signature for the given PDF Signature Sictionary covers the whole document
	 * 
	 * @param signatureDictionary {@link PdfSignatureDictionary} to check the result for
	 * @return TRUE if the signature covers the whole document, false otherwise
	 */
	boolean isSignatureCoversWholeDocument(PdfSignatureDictionary signatureDictionary);

}
