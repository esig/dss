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

package eu.europa.ec.markt.dss.signature.pades;

import java.io.ByteArrayOutputStream;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.pdf.PDFTimestampService;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
class PAdESLevelBaselineT implements SignatureExtension {

    private final TSPSource tspSource;
    private final CertificateVerifier certificateVerifier;

    public PAdESLevelBaselineT(TSPSource tspSource, CertificateVerifier certificateVerifier) {

        this.tspSource = tspSource;
        this.certificateVerifier = certificateVerifier;
    }

    @Override
    public DSSDocument extendSignatures(final DSSDocument document, final SignatureParameters params) throws DSSException {

        assertExtendSignaturePossible(document);

        final PdfObjFactory factory = PdfObjFactory.getInstance();
        final ByteArrayOutputStream tDoc = new ByteArrayOutputStream();
        final PDFTimestampService timestampService = factory.newTimestampSignatureService();
        timestampService.timestamp(document, tDoc, params, tspSource);
	    final InMemoryDocument inMemoryDocument = new InMemoryDocument(tDoc.toByteArray());
	    inMemoryDocument.setMimeType(MimeType.PDF);
	    return inMemoryDocument;
    }

    private void assertExtendSignaturePossible(final DSSDocument document) {
    }
}
