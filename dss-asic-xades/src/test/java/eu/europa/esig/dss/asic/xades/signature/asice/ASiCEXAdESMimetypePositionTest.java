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
package eu.europa.esig.dss.asic.xades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

class ASiCEXAdESMimetypePositionTest extends AbstractASiCEXAdESTestSignature {

	private DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		DSSDocument doc = new InMemoryDocument(byteArray);

		StringBuilder hex = new StringBuilder(byteArray.length * 2);
		for (byte b : byteArray) {
			hex.append(String.format("%02x", b & 0xff));

		}
		assertEquals("504b0304", hex.substring(0, 8).toLowerCase());

		try (InputStream is = doc.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry entry;
			String name = null;
			while ((entry = zis.getNextEntry()) != null) {
				name = entry.getName();
				break;
			}
			assertEquals("mimetype", name);
			assertEquals(0, entry.getMethod());
			assertNull(entry.getExtra());
		} catch (IOException e1) {
			throw new DSSException(e1);
		}
	}

	@Override
	protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
