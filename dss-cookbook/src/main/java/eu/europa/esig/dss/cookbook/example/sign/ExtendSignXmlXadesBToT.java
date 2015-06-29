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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cookbook.example.Cookbook;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

/**
 * How to extend with XAdES-BASELINE-T
 */
public class ExtendSignXmlXadesBToT extends Cookbook {

	public static void main(final String[] args) throws IOException {

		toExtendDocument = new FileDocument("signedXmlXadesB.xml");

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService xadesService = new XAdESService(certificateVerifier);
		try{
			xadesService.setTspSource(getMockTSPSource());
		}catch (Exception e) {
			new DSSException("Error during MockTspSource",e);
		}

		DSSDocument extendedDocument = xadesService.extendDocument(toExtendDocument, parameters);

		//DSSUtils.copy(extendedDocument.openStream(), System.out);
		InputStream is = new ByteArrayInputStream(extendedDocument.getBytes());
		DSSUtils.saveToFile(is, "target/extendedSignedXmlXadesBToT.xml");
	}
}