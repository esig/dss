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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;

/**
 * Signature timestamp representation
 * This class is only used in case of Document Timestamp (not signature-timestamp from CAdES/CMS)
 */
public class PdfDocTimestampRevision extends PdfCMSRevision {

	private static final long serialVersionUID = -1526261963945359026L;

	private static final Logger LOG = LoggerFactory.getLogger(PdfDocTimestampRevision.class);

	/** The document timestamp token from the revision */
	private final TimestampToken timestampToken;

	/**
	 * Default constructor to create PdfDocTimestampInfo
	 * 
	 * @param signatureDictionary
	 *            					   the signature dictionary
	 * @param timestampFieldNames
	 *            					   list of signature field names
	 * @param signedContent
	 *                                 {@link DSSDocument} the signed data
	 * @param coverCompleteRevision
	 *                                 true if the signature covers all bytes
	 */
	public PdfDocTimestampRevision(PdfSignatureDictionary signatureDictionary, List<String> timestampFieldNames,
								   DSSDocument signedContent, boolean coverCompleteRevision) {
		super(signatureDictionary, timestampFieldNames, signedContent, coverCompleteRevision);
		try {
			timestampToken = new PdfTimestampToken(this);
			timestampToken.matchData(getSignedData());
			if (LOG.isDebugEnabled()) {
				LOG.debug("Created PdfDocTimestampInfo : {}", getByteRange());
			}
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to create a PdfDocTimestampRevision : %s", e.getMessage()), e);
		}
	}

	@Override
	public Date getSigningDate() {
		return timestampToken.getGenerationTime();
	}

	/**
	 * Returns the corresponding {@code TimestampToken}
	 *
	 * @return {@link TimestampToken}
	 */
	public TimestampToken getTimestampToken() {
		return timestampToken;
	}

}
