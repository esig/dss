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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.timestamp.PAdESTimestampService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.SecureRandomProvider;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

/**
 * PAdES Baseline T signature
 */
class PAdESLevelBaselineT implements SignatureExtension<PAdESSignatureParameters> {

	private final TSPSource tspSource;
	private final IPdfObjFactory pdfObjectFactory;
	
	private SecureRandomProvider secureRandomProvider;

	protected PAdESLevelBaselineT(TSPSource tspSource, IPdfObjFactory pdfObjectFactory) {
		this.tspSource = tspSource;
		this.pdfObjectFactory = pdfObjectFactory;
	}

	@Override
	public DSSDocument extendSignatures(final DSSDocument document, final PAdESSignatureParameters params) throws DSSException {
		// Will add a DocumentTimeStamp. signature-timestamp (CMS) is impossible to add while extending
		return timestampDocument(document, params.getSignatureTimestampParameters(), params.getPasswordProtection());
	}
	
	protected DSSDocument timestampDocument(final DSSDocument document, final PAdESTimestampParameters timestampParameters, final String pwd) {
		PAdESTimestampService padesTimestampService = new PAdESTimestampService(tspSource, newPdfSignatureService());
		timestampParameters.setPasswordProtection(pwd);
		return padesTimestampService.timestampDocument(document, timestampParameters);
	}
	
	protected PDFSignatureService newPdfSignatureService() {
		PDFSignatureService signatureTimestampService = pdfObjectFactory.newSignatureTimestampService();
		signatureTimestampService.setSecureRandomProvider(secureRandomProvider);
		return signatureTimestampService;
	}

	/**
	 * Allows to set a {@code SecureRandomProvider} to generate SecureRandom for encrypted documents
	 * @param secureRandomProvider
	 */
	public void setSecureRandomProvider(SecureRandomProvider secureRandomProvider) {
		this.secureRandomProvider = secureRandomProvider;
	}

}
