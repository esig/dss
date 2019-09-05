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

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

@SuppressWarnings("serial")
public abstract class AbstractSignatureService<SP extends AbstractSignatureParameters> implements DocumentSignatureService<SP> {

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
		if (certificateVerifier == null) {
			throw new NullPointerException("CertificateVerifier cannot be null !");
		}
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
		if (parameters.isSignWithExpiredCertificate() || (parameters.getSigningCertificate() == null && parameters.isGenerateTBSWithoutCertificate())) {
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

	protected String getFinalFileName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level, ASiCContainerType containerType) {
		StringBuilder finalName = new StringBuilder();

		String originalName = null;
		if (containerType != null) {
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
			finalName.append("-signed-");
		} else if (SigningOperation.EXTEND.equals(operation)) {
			finalName.append("-extended-");
		}

		finalName.append(Utils.lowerCase(level.name().replaceAll("_", "-")));
		finalName.append('.');

		if (containerType != null) {
			switch (containerType) {
			case ASiC_S:
				finalName.append("asics");
				break;
			case ASiC_E:
				finalName.append("asice");
				break;
			default:
				break;
			}
		} else {
			SignatureForm signatureForm = level.getSignatureForm();
			switch (signatureForm) {
			case XAdES:
				finalName.append("xml");
				break;
			case CAdES:
				finalName.append("pkcs7");
				break;
			case PAdES:
				finalName.append("pdf");
				break;
			default:
				break;
			}
		}

		return finalName.toString();
	}

	protected String getFinalFileName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level) {
		return getFinalFileName(originalFile, operation, level, null);
	}

}
