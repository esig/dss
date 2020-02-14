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
package eu.europa.esig.dss.cookbook.example.sign;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * How to extend with XAdES-BASELINE-T
 */
public class ExtendSignXmlXadesBToTTest extends CookbookTools {

	@Test
	public void extendXAdESBToT() throws Exception {

		// tag::demo[]

		DSSDocument document = new FileDocument("src/test/resources/signature-pool/signedXmlXadesB.xml");

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService xadesService = new XAdESService(certificateVerifier);
		xadesService.setTspSource(getOnlineTSPSource());

		DSSDocument extendedDocument = xadesService.extendDocument(document, parameters);

		// end::demo[]

		testFinalDocument(extendedDocument);
	}
}
