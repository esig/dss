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
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;

public class JAdESSignatureParameters extends AbstractSignatureParameters<JAdESTimestampParameters> {
	
	/**
	 * Defines if certificate chain binaries must be included into the signed header ('x5c' attribute)
	 */
	private boolean includeCertificateChainBinaries = true;
	
	/**
	 * Defines if the signature must incorporate its MimeType definition in the signed header ('typ' attribute)
	 */
	private boolean includeSignatureType = true;
	
	/**
	 * The DigestAlgorithm used to create a reference to a signing certificate, 
	 * namely 'x5t#256' for SHA256 or 'x5t#o' for other algorithms
	 */
	private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA256;
	
	/**
	 * Defines a JWS signature type according to RFC 7515, 3. JSON Web Signature (JWS) Overview
	 * 
	 * Default: JWSSerializationType.COMPACT_SERIALIZATION
	 */
	private JWSSerializationType jwsSerializationType = JWSSerializationType.COMPACT_SERIALIZATION;
	
	/**
	 * Defines a used 'sigD' mechanism for a detached signature
	 */
	private SigDMechanism sigDMechanism = SigDMechanism.OBJECT_ID_BY_URI_HASH;

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
	 * Defines if the signature MimeType string must be included into the signed header ('typ' attribute)
	 * 
	 * @return TRUE if the MimeType string of the produced signature must be included, FALSE otherwise
	 */
	public boolean isIncludeSignatureType() {
		return includeSignatureType;
	}

	/**
	 * Sets if the signature MimeType string must be included into the signed header ('typ' attribute)
	 * Default: TRUE (the signature MimeTipe will be included into the signed header)
	 *
	 * @param includeSignatureType if the signature MimeType be included into the signed header
	 */
	public void setIncludeSignatureType(boolean includeSignatureType) {
		this.includeSignatureType = includeSignatureType;
	}

	/**
	 * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm)}.
	 *
	 * @return {@link DigestAlgorithm} to be used for signing certificate digest representation
	 */
	public DigestAlgorithm getSigningCertificateDigestMethod() {
		return signingCertificateDigestMethod;
	}

	/**
	 * The digest method indicates the digest algorithm to be used to calculate the certificate digest
	 * to define a signing certificate ('x5t#256' for SHA256 or 'x5t#o' for other algorithms)
	 * Default: DigestAlgorithm.SHA256 ('x5t#256' attribute will be created)
	 *
	 * @param signingCertificateDigestMethod {@link DigestAlgorithm} to be used
	 */
	public void setSigningCertificateDigestMethod(final DigestAlgorithm signingCertificateDigestMethod) {
		Objects.requireNonNull(signingCertificateDigestMethod, "SigningCertificateDigestMethod cannot be null!");
		this.signingCertificateDigestMethod = signingCertificateDigestMethod;
	}

	/**
	 * Gets JWSSerializationType
	 * 
	 * @return {@link JWSSerializationType}
	 */
	public JWSSerializationType getJwsSerializationType() {
		return jwsSerializationType;
	}

	/**
	 * Sets the JWSSerializationType
	 * Default: JWSSerializationType.COMPACT_SERIALIZATION
	 * 
	 * @param jwsSerializationType {@link JWSSerializationType}
	 */
	public void setJwsSerializationType(JWSSerializationType jwsSerializationType) {
		Objects.requireNonNull(jwsSerializationType, "JWSSerializationType cannot be null!");
		this.jwsSerializationType = jwsSerializationType;
	}

	/**
	 * Returns a SigDMechanism to use
	 * 
	 * @return {@link SigDMechanism}
	 */
	public SigDMechanism getSigDMechanism() {
		return sigDMechanism;
	}

	/**
	 * Sets SigDMechanism to use for a Detached signature
	 * 
	 * @param sigDMechanism {@link SigDMechanism}
	 */
	public void setSigDMechanism(SigDMechanism sigDMechanism) {
		Objects.requireNonNull(sigDMechanism, "sigDMechanism cannot be null!");
		this.sigDMechanism = sigDMechanism;
	}

}
