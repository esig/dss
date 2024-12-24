/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

/**
 * PAdES Baseline LTA signature
 */
class PAdESLevelBaselineLTA extends PAdESLevelBaselineLT {

	/**
	 * The default constructor
	 *
	 * @param tspSource {@link TSPSource} to use
	 * @param certificateVerifier {@link CertificateVerifier}
	 * @param pdfObjectFactory {@link IPdfObjFactory}
	 */
	public PAdESLevelBaselineLTA(TSPSource tspSource, CertificateVerifier certificateVerifier, final IPdfObjFactory pdfObjectFactory) {
		super(tspSource, certificateVerifier, pdfObjectFactory);
	}

	@Override
	public DSSDocument extendSignatures(DSSDocument document, PAdESSignatureParameters parameters) throws DSSException {
		// check if needed to extend with PAdESLevelBaselineLT
		document = super.extendSignatures(document, parameters);
		
		// Will add a Document TimeStamp (not CMS)
		return timestampDocument(document, parameters.getArchiveTimestampParameters(),
				parameters.getPasswordProtection(), getArchiveTimestampService());
	}

	/**
	 * This method returns a {@code PDFSignatureService} to be used for an archive timestamp creation
	 *
	 * @return {@link PDFSignatureService}
	 */
	private PDFSignatureService getArchiveTimestampService() {
		return pdfObjectFactory.newArchiveTimestampService();
	}

}
