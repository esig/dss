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

import java.io.IOException;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.tsp.TSPSource;

class PdfBoxDocTimeStampService extends PdfBoxSignatureService implements PDFTimestampService {

	/**
	 * A timestamp sub-filter value.
	 */
	public static final COSName SUB_FILTER_ETSI_RFC3161 = COSName.getPDFName("ETSI.RFC3161");

	@Override
	protected COSName getType() {
		return COSName.DOC_TIME_STAMP;
	}

	@Override
	protected COSName getFilter(PAdESSignatureParameters parameters) {
		if (Utils.isStringNotEmpty(parameters.getTimestampFilter())) {
			return COSName.getPDFName(parameters.getTimestampFilter());
		}
		return PDSignature.FILTER_ADOBE_PPKLITE;
	}

	@Override
	protected COSName getSubFilter(PAdESSignatureParameters parameters) {
		if (Utils.isStringNotEmpty(parameters.getTimestampSubFilter())) {
			return COSName.getPDFName(parameters.getTimestampSubFilter());
		}
		return SUB_FILTER_ETSI_RFC3161;
	}

	@Override
	public DSSDocument timestamp(final DSSDocument document, final PAdESSignatureParameters parameters, final TSPSource tspSource) throws DSSException {

		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		final byte[] digest = digest(document, parameters, timestampDigestAlgorithm);
		final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digest);
		final byte[] encoded = DSSASN1Utils.getEncoded(timeStampToken);
		return sign(document, encoded, parameters, timestampDigestAlgorithm);
	}

	@Override
	protected SignatureOptions createSignatureOptions(PDDocument pdDocument, PAdESSignatureParameters parameters)
			throws IOException {
		SignatureImageParameters signatureImageParameters = parameters.getTimestampImageParameters();
		return visibleSignatureDrawer.createVisualSignature(pdDocument, signatureImageParameters);
	}


}