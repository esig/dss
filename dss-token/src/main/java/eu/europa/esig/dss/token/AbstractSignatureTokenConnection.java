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
package eu.europa.esig.dss.token;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

/**
 *
 */
public abstract class AbstractSignatureTokenConnection implements SignatureTokenConnection {

	protected static final Logger LOG = LoggerFactory.getLogger(AbstractSignatureTokenConnection.class);

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {
		return sign(toBeSigned, digestAlgorithm, null, keyEntry);
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf, DSSPrivateKeyEntry keyEntry)
			throws DSSException {
		if (!(keyEntry instanceof KSPrivateKeyEntry)) {
			throw new IllegalArgumentException("Only KSPrivateKeyEntry are supported");
		}

		final EncryptionAlgorithm encryptionAlgorithm = keyEntry.getEncryptionAlgorithm();
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm, mgf);
		final String javaSignatureAlgorithm = signatureAlgorithm.getJCEId();
		LOG.info("Signature algorithm : {}", javaSignatureAlgorithm);

		try {
			final Signature signature = getSignatureInstance(javaSignatureAlgorithm);
			signature.initSign(((KSPrivateKeyEntry) keyEntry).getPrivateKey());

			if (mgf != null) {
				signature.setParameter(createPSSParam(digestAlgorithm));
			}

			signature.update(toBeSigned.getBytes());
			final byte[] signatureValue = signature.sign();
			SignatureValue value = new SignatureValue();
			value.setAlgorithm(signatureAlgorithm);
			value.setValue(signatureValue);
			return value;
		} catch (Exception e) {
			throw new DSSException(e);
		}

	}

	protected Signature getSignatureInstance(final String javaSignatureAlgorithm) throws NoSuchAlgorithmException {
		return Signature.getInstance(javaSignatureAlgorithm);
	}

	private AlgorithmParameterSpec createPSSParam(DigestAlgorithm digestAlgo) {
		String digestJavaName = digestAlgo.getJavaName();
		return new PSSParameterSpec(digestJavaName, "MGF1", new MGF1ParameterSpec(digestJavaName), digestAlgo.getSaltLength(), 1);
	}
}