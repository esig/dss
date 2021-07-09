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
package eu.europa.esig.dss;

import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.SignatureParametersBuilder;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.LinkedList;
import java.util.List;

/**
 * An abstract class to build a signature parameters instance
 *
 * @param <SP> {@code AbstractSignatureParameters}
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractSignatureParametersBuilder<SP extends AbstractSignatureParameters> implements SignatureParametersBuilder<SP> {
	
	/**
	 * A signing certificate to be used for a signature creation
	 */
	private final CertificateToken signingCertificate;

	/**
	 * A certificate chain of the signing certificate
	 */
	private List<CertificateToken> certificateChain;
	
	/**
	 * BLevelParameters
	 */
	private BLevelParameters bLevelParams = new BLevelParameters();
	
	/**
	 * The default constructor
	 * 
	 * @param signingCertificate {@link CertificateToken}
	 */
	protected AbstractSignatureParametersBuilder(CertificateToken signingCertificate) {
		this(signingCertificate, new LinkedList<>());
	}

	/**
	 * A constructor with a certificateChain
	 * 
	 * @param signingCertificate {@link CertificateToken}
	 * @param certificateChain a list of {@link CertificateToken}s
	 */
	protected AbstractSignatureParametersBuilder(CertificateToken signingCertificate, List<CertificateToken> certificateChain) {
		this.signingCertificate = signingCertificate;
		this.certificateChain = certificateChain;
	}
	
	/**
	 * Initialize and return empty signature parameters
	 * 
	 * @return {@code SP} signature parameters
	 */
	protected abstract SP initParameters();
	
	/**
	 * Returns {@code BLevelParameters}
	 * 
	 * @return {@link BLevelParameters}
	 */
	public BLevelParameters bLevel() {
		return bLevelParams;
	}

	/**
	 * Sets a BLevelParameters (e.g. a SigningDate)
	 * 
	 * @param bLevelParams {@link BLevelParameters} to be used
	 * @return the builder
	 */
	public AbstractSignatureParametersBuilder<SP> setBLevelParams(BLevelParameters bLevelParams) {
		this.bLevelParams = bLevelParams;
		return this;
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public SP build() {
		SP signatureParameters = initParameters();
		signatureParameters.setSigningCertificate(signingCertificate);
		signatureParameters.setCertificateChain(certificateChain);
		signatureParameters.setBLevelParams(bLevelParams);
		return signatureParameters;
	}

}
