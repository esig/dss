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

package eu.europa.ec.markt.dss.validation102853.asic;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.validation.DocumentValidator;
import eu.europa.ec.markt.dss.validation102853.cades.CMSDocumentValidator;

/**
 * Validator for ASiC timeStampToken
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
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
			throw new DSSNullException(DSSDocument.class, "detachedContents");
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
