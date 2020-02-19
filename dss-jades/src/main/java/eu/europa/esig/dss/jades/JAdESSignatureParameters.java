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
package eu.europa.esig.dss.jades;

import java.util.Objects;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class JAdESSignatureParameters extends AbstractSignatureParameters<JAdESTimestampParameters> {
	
	/**
	 * Defines if certificate chain binaries must be included into the signed header ('x5c' attribute)
	 */
	private boolean includeCertificateChainBinaries = true;
	
	/**
	 * The DigestAlgorithm used to create a reference to a signing certificate, 
	 * namely 'x5t#256' for SHA256 or 'x5t#o' for other algorithms
	 */
	private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA256;

	@Override
	public JAdESTimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new JAdESTimestampParameters();
		}
		return contentTimestampParameters;
	}

	/**
	 * Defines if complete certificate chain binaries must be included into the signed header ('x5c' attribute)
	 * 
	 * @return TRUE if the certificate chain must be included, FALSE otherwise
	 */
	public boolean isIncludeCertificateChain() {
		return includeCertificateChainBinaries;
	}

	/**
	 * Sets if complete certificate chain binaries must be included into the signed header
	 * Default: TRUE (the complete binaries will be included into the signed header)
	 * 
	 * @param includeCertificateChain if the certificate chain binaries must be included into the signed header
	 */
	public void setIncludeCertificateChain(boolean includeCertificateChain) {
		this.includeCertificateChainBinaries = includeCertificateChain;
	}

	/**
	 * The digest method indicates the digest algorithm to be used to calculate the certificate digest
	 * to define a signing certificate ('x5t#256' for SHA256 or 'x5t#o' for other algorithms)
	 *
	 * @param signingCertificateDigestMethod {@link DigestAlgorithm} to be used
	 */
	public void setSigningCertificateDigestMethod(final DigestAlgorithm signingCertificateDigestMethod) {
		Objects.requireNonNull(signingCertificateDigestMethod, "SigningCertificateDigestMethod cannot be null!");
		this.signingCertificateDigestMethod = signingCertificateDigestMethod;
	}

	/**
	 * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm)}.
	 *
	 * @return {@link DigestAlgorithm} to be used for signing certificate digest representation
	 */
	public DigestAlgorithm getSigningCertificateDigestMethod() {
		return signingCertificateDigestMethod;
	}

}
