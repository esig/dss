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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import java.security.PublicKey;

/**
 * Validates integrity of a CAdES signature
 */
public class CAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {

	/** The corresponding SignerInformation */
	private final SignerInformation signerInformation;

	/** The instance of the verifier builder */
	private final JcaSimpleSignerInfoVerifierBuilder verifierBuilder;

	/**
	 * The default constructor
	 *
	 * @param signerInformation {@link SignerInformation} to be validated
	 */
	public CAdESSignatureIntegrityValidator(final SignerInformation signerInformation) {
		this.signerInformation = signerInformation;
		this.verifierBuilder = instantiateVerifier();
	}
	
	private JcaSimpleSignerInfoVerifierBuilder instantiateVerifier() {
		final JcaSimpleSignerInfoVerifierBuilder jcaVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
		jcaVerifierBuilder.setProvider(DSSSecurityProvider.getSecurityProviderName());
		return jcaVerifierBuilder;
	}

	@Override
	protected boolean verify(PublicKey publicKey) throws DSSException {
		try {
			final SignerInformationVerifier signerInformationVerifier = verifierBuilder.build(publicKey);
			return signerInformation.verify(signerInformationVerifier);
		} catch (CMSSignerDigestMismatchException e) {
			throw new DSSException(String.format("Unable to validate CMS Signature : %s", e.getMessage()));
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to validate CMS Signature : %s", e.getMessage()), e);
		}
	}

}
