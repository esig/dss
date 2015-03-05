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
package eu.europa.ec.markt.dss.validation102853.asic;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.validation.DocumentValidator;
import eu.europa.ec.markt.dss.validation102853.cades.CMSDocumentValidator;

/**
 * Validator for ASiC timeStampToken
 */
public class ASiCTimestampDocumentValidator extends CMSDocumentValidator {

	private DocumentValidator nextValidator;

	/**
	 * This variable defines the sequence of the validator related to a document to validate. It's only used with ASiC-E container
	 */
	private TimeStampToken timeStampToken;

	/**
	 * In case of a detached signature this is the signed document.
	 */
	protected List<DSSDocument> timestampExternalContents;

	/**
	 * The default constructor for ASiCXMLDocumentValidator.
	 *
	 * @param timestamp        {@code DSSDocument} representing the timestamp to validate
	 * @param detachedContents the {@code List} containing the potential signed documents
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	public ASiCTimestampDocumentValidator(final DSSDocument timestamp, final List<DSSDocument> detachedContents) throws DSSException {

		super(timestamp);

		try {
			timeStampToken = new TimeStampToken(cmsSignedData);
		} catch (TSPException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
		if (detachedContents == null || detachedContents.size() == 0) {
			throw new NullPointerException("detachedContents");
		}
		timestampExternalContents = detachedContents;
	}

	@Override
	public void setNextValidator(final DocumentValidator validator) {

		nextValidator = validator;
	}

	@Override
	public DocumentValidator getNextValidator() {
		return nextValidator;
	}
}
