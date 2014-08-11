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

package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.OutputStream;
import java.util.Map;

import org.apache.pdfbox.cos.COSName;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PDFTimestampService;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

class PdfBoxDocTimeStampService extends PdfBoxSignatureService implements PDFSignatureService, PDFTimestampService {

    /**
     * A timestamp sub-filter value.
     */
    public static final COSName SUB_FILTER_ETSI_RFC3161 = COSName.getPDFName("ETSI.RFC3161");

    protected COSName getSubFilter() {
        return SUB_FILTER_ETSI_RFC3161;
    }

    @Override
    public void timestamp(final DSSDocument document, final OutputStream signedStream, final SignatureParameters parameters, final TSPSource tspSource,
                          final Map.Entry<String, PdfDict>... dictToAdd) throws DSSException {

        final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
        final byte[] digest = digest(document.openStream(), parameters, timestampDigestAlgorithm, dictToAdd);
        final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digest);
        final byte[] encoded = DSSASN1Utils.getEncoded(timeStampToken);
        sign(document.openStream(), encoded, signedStream, parameters, timestampDigestAlgorithm, dictToAdd);
    }
}
