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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;

/**
 * PAdES Baseline LTA signature
 */
class PAdESLevelBaselineLTA implements SignatureExtension<PAdESSignatureParameters> {

	private final TSPSource tspSource;
	private final IPdfObjFactory pdfObjectFactory;
	private final PAdESLevelBaselineLT padesLevelBaselineLT;
	private final CertificateVerifier certificateVerifier;

	public PAdESLevelBaselineLTA(TSPSource tspSource, CertificateVerifier certificateVerifier, final IPdfObjFactory pdfObjectFactory) {
		this.tspSource = tspSource;
		this.pdfObjectFactory = pdfObjectFactory;
		this.padesLevelBaselineLT = new PAdESLevelBaselineLT(tspSource, certificateVerifier, pdfObjectFactory);
		this.certificateVerifier = certificateVerifier;
	}

	@Override
	public DSSDocument extendSignatures(DSSDocument document, PAdESSignatureParameters parameters) throws DSSException {

		// check if needed to extends with PAdESLevelBaselineLT
		final PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
		pdfDocumentValidator.setCertificateVerifier(certificateVerifier);

		document = padesLevelBaselineLT.extendSignatures(document, parameters);

		final PDFSignatureService signatureService = pdfObjectFactory.newArchiveTimestampService();
		final DigestAlgorithm timestampDigestAlgorithm = parameters.getArchiveTimestampParameters().getDigestAlgorithm();

		// Will add a Document TimeStamp (not CMS)
		final byte[] digest = signatureService.digest(document, parameters);
		final TimestampBinary timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digest);
		final byte[] encoded = DSSASN1Utils.getDEREncoded(timeStampToken);
		return signatureService.sign(document, encoded, parameters);
	}

}
