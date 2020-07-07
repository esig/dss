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
package eu.europa.esig.dss.pades.validation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.ByteRange;
import eu.europa.esig.dss.validation.SignatureIdentifier;

public final class PAdESSignatureIdentifier extends SignatureIdentifier {

	private static final long serialVersionUID = -7672798196825794558L;

	public PAdESSignatureIdentifier(PAdESSignature padesSignature) {
		super(buildBinaries(padesSignature));
	}
	
	private static byte[] buildBinaries(PAdESSignature padesSignature) {
		final CertificateToken certificateToken = padesSignature.getSigningCertificateToken();
		final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
		return SignatureIdentifier.buildSignatureIdentifier(padesSignature.getSigningTime(), identifier, getDigestOfByteRange(padesSignature.getPdfRevision()));
	}

	private static String getDigestOfByteRange(PdfSignatureRevision pdfSignatureRevision) {
		ByteRange signatureByteRange = pdfSignatureRevision.getByteRange();
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			baos.write(signatureByteRange.toString().getBytes());
			return DSSUtils.getMD5Digest(baos.toByteArray());
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read byteRange : %s", signatureByteRange));
		}
	}

}
