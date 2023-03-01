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
package eu.europa.esig.dss.pades.timestamp;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.util.Objects;

/**
 * The service to timestamp a PDF
 */
public class PAdESTimestampService {

	/** TSP source to obtain a timestamp */
	private final TSPSource tspSource;

	/** The signature service implementation to use */
	private final PDFSignatureService pdfSignatureService;

	/**
	 * Constructor with {@code TSPSource} instantiating a default {@code PDFSignatureService}
	 * for an archive (document) timestamp creation
	 *
	 * @param tspSource {@link TSPSource}
	 */
	public PAdESTimestampService(TSPSource tspSource) {
		this(tspSource, new ServiceLoaderPdfObjFactory().newArchiveTimestampService());
	}

	/**
	 * The default constructor
	 *
	 * @param tspSource {@link TSPSource} to request the timestamp
	 * @param pdfSignatureService {@link PDFSignatureService} to use
	 */
	public PAdESTimestampService(TSPSource tspSource, PDFSignatureService pdfSignatureService) {
		Objects.requireNonNull(tspSource, "TSPSource shall be provided!");
		Objects.requireNonNull(pdfSignatureService, "PDFSignatureService shall be provided!");
		this.tspSource = tspSource;
		this.pdfSignatureService = pdfSignatureService;
	}

	/**
	 * Timestamp the document
	 *
	 * @param document {@link DSSDocument} to timestamp
	 * @param params {@link PAdESTimestampParameters}
	 * @return {@link DSSDocument} timestamped
	 */
	public DSSDocument timestampDocument(final DSSDocument document, final PAdESTimestampParameters params) {
		final DSSMessageDigest messageDigest = pdfSignatureService.messageDigest(document, params);
		final TimestampBinary timeStampToken = tspSource.getTimeStampResponse(messageDigest.getAlgorithm(), messageDigest.getValue());
		final byte[] encoded = DSSASN1Utils.getDEREncoded(timeStampToken);
		return pdfSignatureService.sign(document, encoded, params);
	}

}
