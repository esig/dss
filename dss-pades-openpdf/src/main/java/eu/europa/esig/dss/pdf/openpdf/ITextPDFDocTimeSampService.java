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
package eu.europa.esig.dss.pdf.openpdf;

import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * Implementation of PDFSignatureService using iText
 *
 */
class ITextPDFDocTimeSampService extends ITextPDFSignatureService implements PDFTimestampService {

	ITextPDFDocTimeSampService() {
	}

	@Override
	protected String getType() {
		return PAdESConstants.TIMESTAMP_TYPE;
	}

	@Override
	protected String getFilter(PAdESSignatureParameters parameters) {
		if (Utils.isStringNotEmpty(parameters.getTimestampFilter())) {
			return parameters.getTimestampFilter();
		}
		return PAdESConstants.TIMESTAMP_DEFAULT_FILTER;
	}

	@Override
	protected String getSubFilter(PAdESSignatureParameters parameters) {
		if (Utils.isStringNotEmpty(parameters.getTimestampSubFilter())) {
			return parameters.getTimestampSubFilter();
		}
		return PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER;
	}

	@Override
	public DSSDocument timestamp(DSSDocument document, PAdESSignatureParameters parameters, TSPSource tspSource) throws DSSException {
		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		final byte[] digest = digest(document, parameters, timestampDigestAlgorithm);
		final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digest);
		final byte[] encoded = CMSUtils.getEncoded(timeStampToken.toCMSSignedData());
		return sign(document, encoded, parameters, timestampDigestAlgorithm);
	}

}
