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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * The abstract implementation of a remote token connection
 */
public abstract class AbstractSignatureTokenConnection implements SignatureTokenConnection {

	protected static final Logger LOG = LoggerFactory.getLogger(AbstractSignatureTokenConnection.class);

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {
		return sign(toBeSigned, digestAlgorithm, null, keyEntry);
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf,
			DSSPrivateKeyEntry keyEntry) throws DSSException {
		final EncryptionAlgorithm encryptionAlgorithm = keyEntry.getEncryptionAlgorithm();
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm,
				digestAlgorithm, mgf);
		final String javaSignatureAlgorithm = signatureAlgorithm.getJCEId();
		final byte[] bytes = toBeSigned.getBytes();
		AlgorithmParameterSpec param = null;
		if (mgf != null) {
			param = createPSSParam(digestAlgorithm);
		}

		try {
			final byte[] signatureValue = sign(bytes, javaSignatureAlgorithm, param, keyEntry);
			SignatureValue value = new SignatureValue();
			value.setAlgorithm(signatureAlgorithm);
			value.setValue(signatureValue);
			return value;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	public SignatureValue signDigest(Digest digest, DSSPrivateKeyEntry keyEntry) throws DSSException {
		return signDigest(digest, null, keyEntry);
	}

	@Override
	public SignatureValue signDigest(Digest digest, MaskGenerationFunction mgf, DSSPrivateKeyEntry keyEntry)
			throws DSSException {
		final EncryptionAlgorithm encryptionAlgorithm = keyEntry.getEncryptionAlgorithm();
		final SignatureAlgorithm signatureAlgorithmNONE = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, null,
				mgf);
		final String javaSignatureAlgorithm = signatureAlgorithmNONE.getJCEId();
		final byte[] digestedBytes = digest.getValue();
		AlgorithmParameterSpec param = null;
		if (mgf != null) {
			param = createPSSParam(digest.getAlgorithm());
		}

		try {
			final byte[] signatureValue = sign(digestedBytes, javaSignatureAlgorithm, param, keyEntry);
			SignatureValue value = new SignatureValue();
			value.setAlgorithm(SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digest.getAlgorithm(), mgf));
			value.setValue(signatureValue);
			return value;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	private byte[] sign(final byte[] bytes, final String javaSignatureAlgorithm, final AlgorithmParameterSpec param,
			final DSSPrivateKeyEntry keyEntry) throws GeneralSecurityException {
		if (!(keyEntry instanceof KSPrivateKeyEntry)) {
			throw new IllegalArgumentException("Only KSPrivateKeyEntry are supported");
		}
		LOG.info("Signature algorithm : {}", javaSignatureAlgorithm);
		final Signature signature = getSignatureInstance(javaSignatureAlgorithm);
		if (param != null) {
			signature.setParameter(param);
		}
		signature.initSign(((KSPrivateKeyEntry) keyEntry).getPrivateKey());
		signature.update(bytes);
		return signature.sign();
	}

	/**
	 * Returns the {@code java.security.Signature} instance for the given {@code javaSignatureAlgorithm}
	 *
	 * @param javaSignatureAlgorithm {@link String} representing the Java name of a signature algorithm
	 * @return {@link Signature}
	 * @throws NoSuchAlgorithmException if the algorithm is not found
	 */
	protected Signature getSignatureInstance(final String javaSignatureAlgorithm) throws NoSuchAlgorithmException {
		return Signature.getInstance(javaSignatureAlgorithm);
	}

	/**
	 * Creates {@code java.security.spec.AlgorithmParameterSpec} for the given {@code digestAlgo}
	 *
	 * @param digestAlgo {@link DigestAlgorithm}
	 * @return {@link AlgorithmParameterSpec}
	 */
	protected AlgorithmParameterSpec createPSSParam(DigestAlgorithm digestAlgo) {
		String digestJavaName = digestAlgo.getJavaName();
		return new PSSParameterSpec(digestJavaName, "MGF1", new MGF1ParameterSpec(digestJavaName), digestAlgo.getSaltLength(), 1);
	}

}
