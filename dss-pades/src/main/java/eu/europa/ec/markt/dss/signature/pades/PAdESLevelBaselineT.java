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
package eu.europa.ec.markt.dss.signature.pades;

import java.io.ByteArrayOutputStream;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.PAdESSignatureParameters;
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
 *
 *
 *
 *
 *
 *
 */
class PAdESLevelBaselineT implements SignatureExtension<PAdESSignatureParameters> {

	private final TSPSource tspSource;
	private final CertificateVerifier certificateVerifier;

	public PAdESLevelBaselineT(TSPSource tspSource, CertificateVerifier certificateVerifier) {

		this.tspSource = tspSource;
		this.certificateVerifier = certificateVerifier;
	}

	@Override
	public DSSDocument extendSignatures(final DSSDocument document, final PAdESSignatureParameters params) throws DSSException {

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
