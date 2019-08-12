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
package eu.europa.esig.dss.pades;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.apache.pdfbox.preflight.PreflightDocument;
import org.apache.pdfbox.preflight.ValidationResult;
import org.apache.pdfbox.preflight.ValidationResult.ValidationError;
import org.apache.pdfbox.preflight.parser.PreflightParser;
import org.apache.pdfbox.preflight.utils.ByteArrayDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSDocument;

public final class PDFAUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PDFAUtils.class);

	private PDFAUtils() {
	}

	public static boolean validatePDFAStructure(DSSDocument signedDocument) {
		try (InputStream is = signedDocument.openStream()) {
			PreflightParser parser = new PreflightParser(new ByteArrayDataSource(is));
			parser.parse();
			PreflightDocument preflightDocument = parser.getPreflightDocument();
			preflightDocument.validate();
			ValidationResult result = preflightDocument.getResult();
			List<ValidationError> errorsList = result.getErrorsList();
			for (ValidationError validationError : errorsList) {
				LOG.info(validationError.getDetails());
			}
			return result.isValid();
		} catch (IOException e) {
			throw new DSSException("Unable to validate PDFA structure", e);
		}
	}
}
