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
package eu.europa.esig.dss.pdf.pdfbox;

import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.cos.COSName;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.x509.tsp.TSPSource;

class PdfBoxDocTimeStampService extends PdfBoxSignatureService implements PDFSignatureService, PDFTimestampService {

	/**
	 * A timestamp sub-filter value.
	 */
	public static final COSName SUB_FILTER_ETSI_RFC3161 = COSName.getPDFName("ETSI.RFC3161");

	@Override
	protected COSName getSubFilter() {
		return SUB_FILTER_ETSI_RFC3161;
	}

	@Override
	protected COSName getType() {
		return COSName.DOC_TIME_STAMP;
	}

	@Override
	public void timestamp(final DSSDocument document, final OutputStream signedStream, final PAdESSignatureParameters parameters, final TSPSource tspSource) throws DSSException {

		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		InputStream inputStream = document.openStream();
		final byte[] digest = digest(inputStream, parameters, timestampDigestAlgorithm);
		IOUtils.closeQuietly(inputStream);
		final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digest);
		final byte[] encoded = DSSASN1Utils.getEncoded(timeStampToken);
		inputStream = document.openStream();
		sign(inputStream, encoded, signedStream, parameters, timestampDigestAlgorithm);
		IOUtils.closeQuietly(inputStream);
	}

}