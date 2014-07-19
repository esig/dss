/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class AbstractSignatureService implements DocumentSignatureService {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	protected TSPSource tspSource;

	final protected CertificateVerifier certificateVerifier;

	/**
	 * To construct a signature service the <code>CertificateVerifier</code> must be set and cannot be null.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	protected AbstractSignatureService(final CertificateVerifier certificateVerifier) {

		if (certificateVerifier == null) {

			throw new DSSNullException(CertificateVerifier.class);
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
	 * @param parameters set of driving signing parameters
	 */
	protected void assertSigningDateInCertificateValidityRange(final SignatureParameters parameters) {

		if (parameters.isSignWithExpiredCertificate()) {
			return;
		}
		final X509Certificate signingCertificate = parameters.getSigningCertificate();
		final Date notAfter = signingCertificate.getNotAfter();
		final Date notBefore = signingCertificate.getNotBefore();
		final Date signingDate = parameters.bLevel().getSigningDate();
		if (signingDate.after(notAfter) || signingDate.before(notBefore)) {
			throw new DSSException(
				  String.format("Signing Date (%s) is not in certificate validity range (%s, %s).", signingDate.toString(), notBefore.toString(), notAfter.toString()));
		}
	}
}