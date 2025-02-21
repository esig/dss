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
package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.xades.tsl.TrustedListV5SignatureParametersBuilder;

/**
 * Creates Signature parameters for a Trusted List creation
 * <p>
 * NOTE: the same instance of SignatureParameters shall be used on calls
 * {@code DocumentSignatureService.getDataToSign(...)} and {@code DocumentSignatureService.signDocument(...)}
 *
 * @deprecated since DSS 6.1.1/6.2. Please use {@code TrustedListV5SignatureParametersBuilder} or
 *             {@code TrustedListV6SignatureParametersBuilder} instead.
 */
@Deprecated
public class TrustedListSignatureParametersBuilder extends TrustedListV5SignatureParametersBuilder {
	
	/**
	 * The constructor to build Signature Parameters for a Trusted List signing with respect to ETSI TS 119 612
	 * 
	 * @param signingCertificate {@link CertificateToken} to be used for a signature creation
	 * @param tlXmlDocument {@link DSSDocument} Trusted List XML document to be signed
	 * @deprecated since DSS 6.1.1/6.2. Please use instead
	 *             {@code new TrustedListV5SignatureParametersBuilder(signingCertificate, tlXmlDocument)}
	 */
	@Deprecated
	public TrustedListSignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument tlXmlDocument) {
		super(signingCertificate, tlXmlDocument);
	}

	@Override
	public TrustedListSignatureParametersBuilder setReferenceId(String referenceId) {
		return (TrustedListSignatureParametersBuilder) super.setReferenceId(referenceId);
	}

	@Override
	public TrustedListSignatureParametersBuilder setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		return (TrustedListSignatureParametersBuilder) super.setReferenceDigestAlgorithm(digestAlgorithm);
	}

	@Override
	public TrustedListSignatureParametersBuilder setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		return (TrustedListSignatureParametersBuilder) super.setDigestAlgorithm(digestAlgorithm);
	}

	@Override
	public TrustedListSignatureParametersBuilder setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
		return (TrustedListSignatureParametersBuilder) super.setEncryptionAlgorithm(encryptionAlgorithm);
	}

	@Override
	@Deprecated
	public TrustedListSignatureParametersBuilder setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
		return (TrustedListSignatureParametersBuilder) super.setMaskGenerationFunction(maskGenerationFunction);
	}

	@Override
	public TrustedListSignatureParametersBuilder setBLevelParams(BLevelParameters bLevelParams) {
		return (TrustedListSignatureParametersBuilder) super.setBLevelParams(bLevelParams);
	}

}
