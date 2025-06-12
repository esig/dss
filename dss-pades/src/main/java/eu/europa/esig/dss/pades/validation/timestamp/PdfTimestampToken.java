/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampIdentifierBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;

import java.io.IOException;
import java.util.ArrayList;

/**
 * Specific class for a PDF TimestampToken
 *
 */
public class PdfTimestampToken extends TimestampToken {

	private static final long serialVersionUID = -5410279655319854578L;

	/**
	 * The related PDF revision
	 */
	private PdfDocTimestampRevision pdfRevision;

	/**
	 * The default constructor
	 * 
	 * @param pdfTimestampRevision {@link PdfDocTimestampRevision} related to the current
	 *                             TimestampToken
	 * @throws TSPException if a timestamp parsing issue occurs
	 * @throws IOException  if a reading exception occurs
	 * @throws CMSException if a CMS exception occurs
	 */
	public PdfTimestampToken(final PdfDocTimestampRevision pdfTimestampRevision)
			throws TSPException, IOException, CMSException {
		super(pdfTimestampRevision.getPdfSigDictInfo().getCMS().getDEREncoded(), TimestampType.DOCUMENT_TIMESTAMP, new ArrayList<>());
		// TODO : refactor TimestampToken to init with CMS
		this.pdfRevision = pdfTimestampRevision;
	}

	/**
	 * Returns the current PDF timestamp revision
	 * 
	 * @return {@link PdfRevision}
	 */
	public PdfDocTimestampRevision getPdfRevision() {
		return pdfRevision;
	}

	@Override
	protected TimestampIdentifierBuilder getTimestampIdentifierBuilder() {
		return new PdfTimestampTokenIdentifierBuilder(this);
	}

}
