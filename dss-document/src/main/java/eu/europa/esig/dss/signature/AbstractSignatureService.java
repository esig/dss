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
package eu.europa.esig.dss.signature;

import java.security.Security;
import java.util.Date;
import java.util.Objects;

import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

@SuppressWarnings("serial")
public abstract class AbstractSignatureService<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters> 
				implements DocumentSignatureService<SP, TP> {

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

	protected TSPSource tspSource;

	protected final CertificateVerifier certificateVerifier;

	/**
	 * To construct a signature service the <code>CertificateVerifier</code> must be set and cannot be null.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
	 *            in the context of a signature.
	 */
	protected AbstractSignatureService(final CertificateVerifier certificateVerifier) {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null !");
		this.certificateVerifier = certificateVerifier;
	}

	@Override
	public void setTspSource(final TSPSource tspSource) {
		this.tspSource = tspSource;
	}

	/**
	 * This method raises an exception if the signing rules forbid the use on an expired certificate.
	 *
	 * @param parameters
	 *            set of driving signing parameters
	 */
	protected void assertSigningDateInCertificateValidityRange(final SP parameters) {
		if (parameters.getSigningCertificate() == null) {
			if (parameters.isGenerateTBSWithoutCertificate()) {
				return;
			} else {
				throw new DSSException("Signing Certificate is not defined!");
			}
		} else if (parameters.isSignWithExpiredCertificate()) {
			return;
		}
		final CertificateToken signingCertificate = parameters.getSigningCertificate();
		final Date notAfter = signingCertificate.getNotAfter();
		final Date notBefore = signingCertificate.getNotBefore();
		final Date signingDate = parameters.bLevel().getSigningDate();
		if (signingDate.after(notAfter) || signingDate.before(notBefore)) {
			throw new DSSException(String.format("Signing Date (%s) is not in certificate validity range (%s, %s).", signingDate.toString(),
					notBefore.toString(), notAfter.toString()));
		}
	}

	protected String getFinalArchiveName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level, MimeType containerMimeType) {
		StringBuilder finalName = new StringBuilder();

		String originalName = null;
		if (containerMimeType != null) {
			originalName = "container";
		} else {
			originalName = originalFile.getName();
		}

		if (Utils.isStringNotEmpty(originalName)) {
			int dotPosition = originalName.lastIndexOf('.');
			if (dotPosition > 0) {
				// remove extension
				finalName.append(originalName.substring(0, dotPosition));
			} else {
				finalName.append(originalName);
			}
		} else {
			finalName.append("document");
		}

		if (SigningOperation.SIGN.equals(operation)) {
			finalName.append("-signed");
		} else if (SigningOperation.COUNTER_SIGN.equals(operation)) {
			finalName.append("-counter-signed");
		} else if (SigningOperation.TIMESTAMP.equals(operation)) {
			finalName.append("-timestamped");
		} else if (SigningOperation.EXTEND.equals(operation)) {
			finalName.append("-extended");
		}

		if (level != null) {
			finalName.append('-');
			finalName.append(Utils.lowerCase(level.name().replace("_", "-")));
		}

		String extension = getFileExtensionString(level, containerMimeType);
		if (extension != null) {
			finalName.append('.');
			finalName.append(extension);
		}

		return finalName.toString();
	}
	
	private String getFileExtensionString(SignatureLevel level, MimeType containerMimeType) {
		if (containerMimeType != null) {
			return MimeType.getExtension(containerMimeType);
		} else if (level != null) {
			SignatureForm signatureForm = level.getSignatureForm();
			switch (signatureForm) {
				case XAdES:
					return "xml";
				case CAdES:
					return "pkcs7";
				case PAdES:
					return "pdf";
				case JAdES:
					// TODO : use another extension ?
					return "json";
				default:
					throw new DSSException("Unable to generate a full document name");
			}
		} else {
			return "pdf";
		}
	}

	protected String getFinalFileName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level) {
		return getFinalArchiveName(originalFile, operation, level, null);
	}

	@Override
	public DSSDocument timestamp(DSSDocument toTimestampDocument, TP parameters) {
		throw new UnsupportedOperationException("Unsupported operation for this file format");
	}

}

