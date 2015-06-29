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
package eu.europa.esig.dss.pades.signature;

import java.io.ByteArrayOutputStream;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * PAdES Baseline T signature
 */
class PAdESLevelBaselineT implements SignatureExtension<PAdESSignatureParameters> {

	private final TSPSource tspSource;

	public PAdESLevelBaselineT(TSPSource tspSource) {
		this.tspSource = tspSource;
	}

	@Override
	public DSSDocument extendSignatures(final DSSDocument document, final PAdESSignatureParameters params) throws DSSException {

		// Will add a DocumentTimeStamp. signature-timestamp (CMS) is impossible to add while extending
		final PdfObjFactory factory = PdfObjFactory.getInstance();
		final ByteArrayOutputStream tDoc = new ByteArrayOutputStream();
		final PDFTimestampService timestampService = factory.newTimestampSignatureService();
		timestampService.timestamp(document, tDoc, params, tspSource);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(tDoc.toByteArray());
		inMemoryDocument.setMimeType(MimeType.PDF);
		return inMemoryDocument;
	}

}