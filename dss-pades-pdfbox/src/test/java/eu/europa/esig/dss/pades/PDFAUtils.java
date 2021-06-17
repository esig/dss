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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.verapdf.core.VeraPDFException;
import org.verapdf.pdfa.Foundries;
import org.verapdf.pdfa.PDFAParser;
import org.verapdf.pdfa.PDFAValidator;
import org.verapdf.pdfa.VeraGreenfieldFoundryProvider;
import org.verapdf.pdfa.VeraPDFFoundry;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import org.verapdf.pdfa.results.TestAssertion;
import org.verapdf.pdfa.results.ValidationResult;

public final class PDFAUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PDFAUtils.class);
	private static final VeraPDFFoundry FOUNDRY;

	static {
		VeraGreenfieldFoundryProvider.initialise();
		FOUNDRY = Foundries.defaultInstance();
	}

	private PDFAUtils() {
	}

	public static boolean validatePDFAStructure(DSSDocument signedDocument) {
		try (InputStream is = signedDocument.openStream();
			 PDFAParser parser = FOUNDRY.createParser(is);
			 PDFAValidator validator = FOUNDRY.createValidator(parser.getFlavour(), false)) {
			ValidationResult result = validator.validate(parser);
			result.getTestAssertions().stream()
					.filter(assertion -> assertion.getStatus() == TestAssertion.Status.FAILED)
					.forEach(assertion -> LOG.info(assertion.getMessage()));
			return result.isCompliant();
		} catch (IOException | VeraPDFException e) {
			throw new DSSException("Unable to validate PDFA structure", e);
		}
	}
}
