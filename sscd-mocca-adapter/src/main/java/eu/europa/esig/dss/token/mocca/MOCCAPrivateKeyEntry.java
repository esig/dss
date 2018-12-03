/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * Licensed under the EUPL, Version 1.1 or – as soon they
 * will be approved by the European Commission - subsequent
 * versions of the EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the
 * Licence.
 * 
 * You may obtain a copy of the Licence at:
 * 
 * https://joinup.ec.europa.eu/software/page/eupl
 * 
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the Licence is
 * distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 * 
 * See the Licence for the specific language governing
 * permissions and limitations under the Licence.
 */
package eu.europa.esig.dss.token.mocca;

import java.security.cert.CertificateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import at.gv.egiz.smcc.SignatureCard.KeyboxName;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * A DSSPrivateKeyEntry implementation for the MOCCA framework
 */
public class MOCCAPrivateKeyEntry implements DSSPrivateKeyEntry {

	private static final Logger LOG = LoggerFactory.getLogger(MOCCAPrivateKeyEntry.class);

	private CertificateToken signingCert;

	private KeyboxName keyboxName;

	private int index;

	private byte[] atr;

	private EncryptionAlgorithm encryptionAlgorithm;

	private CertificateToken[] certificateChain = new CertificateToken[1];

	/**
	 * This constructor is used when working with several cards
	 *
	 * @param signingCert the certificate
	 * @param keyboxName  identifies signature usage/algorithm
	 * @param index       the position of this KeyEntry in the overall list
	 * @param atr         the ATR associated with this key
	 */
	public MOCCAPrivateKeyEntry(final byte[] signingCert, final KeyboxName keyboxName, final int index, final byte[] atr) {

		initialise(signingCert, keyboxName, atr);
		this.index = index;
	}

	/**
	 * @param signingCertBinary
	 * @param keyboxName
	 * @param atr
	 * @throws CertificateException
	 * @throws DSSException
	 */
	private void initialise(final byte[] signingCertBinary, final KeyboxName keyboxName, final byte[] atr) {

		this.signingCert = DSSUtils.loadCertificate(signingCertBinary);
		LOG.info(">>>Signing certificate subject name/serial number:  {} / {}", signingCert.getSubjectX500Principal().getName(), signingCert.getSerialNumber());
		this.keyboxName = keyboxName;
		if (keyboxName == null) {

			throw new DSSException("KeyboxName is missing");
		}
		this.atr = atr;
		String encryptionAlgo = signingCert.getPublicKey().getAlgorithm(); // Can be: DH, DSA, RSA & EC
		this.encryptionAlgorithm = EncryptionAlgorithm.forName(encryptionAlgo);
		LOG.info("MOCCA>>>EncryptionAlgorithm from public key: {}", this.encryptionAlgorithm.getName());
		this.certificateChain[0] = this.signingCert;
	}

	@Override
	public CertificateToken getCertificate() {

		return signingCert;
	}

	@Override
	public CertificateToken[] getCertificateChain() {

		return certificateChain;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() throws DSSException {

		return encryptionAlgorithm;
	}

	/**
	 * Gets the signature algorithm used to sign the enclosed certificate.
	 *
	 * @return the name (something like SHA1WithRSA)
	 */
	public String getX509SignatureAlgorithmName() {
		return signingCert.getCertificate().getSigAlgName();
	}

	/**
	 * @return the keyboxName
	 */
	public KeyboxName getKeyboxName() {
		return keyboxName;
	}

	/**
	 * Gets the position of this key in the list of all keys
	 *
	 * @return
	 */
	public int getPos() {
		return index;
	}

	/**
	 * Get the ATR associated with this key
	 *
	 * @return the ATR
	 */
	public byte[] getAtr() {
		return atr;
	}
}
