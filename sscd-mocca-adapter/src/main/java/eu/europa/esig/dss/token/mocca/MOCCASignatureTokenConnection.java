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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import at.gv.egiz.smcc.CardNotSupportedException;
import at.gv.egiz.smcc.SignatureCard;
import at.gv.egiz.smcc.SignatureCard.KeyboxName;
import at.gv.egiz.smcc.SignatureCardFactory;
import at.gv.egiz.smcc.util.SmartCardIO;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.SignatureTokenConnection;

/**
 *
 */
@SuppressWarnings("restriction")
public class MOCCASignatureTokenConnection implements SignatureTokenConnection {

	private static final Logger LOG = LoggerFactory.getLogger(MOCCASignatureTokenConnection.class);

	private PINGUIAdapter callback;

	private List<SignatureCard> _signatureCards;

	/**
	 * Use this constructor when the signature algorithm is not known before the connection is opened. You must set the
	 * SignatureAlgorithm property of the key after the connection has been opened (you can get the SignatureAlgorithm
	 * name from the key)
	 *
	 * @param callback
	 *            provides the PIN
	 */
	public MOCCASignatureTokenConnection(PasswordInputCallback callback) {

		this.callback = new PINGUIAdapter(callback);
	}

	public void set_signatureCards(List<SignatureCard> _signatureCards) {
		this._signatureCards = _signatureCards;
	}

	@Override
	public void close() {

		if (_signatureCards != null) {
			for (SignatureCard c : _signatureCards) {
				c.disconnect(true);
			}
			_signatureCards.clear();
			_signatureCards = null;
		}
	}

	private List<SignatureCard> getSignatureCards() {

		if (_signatureCards == null) {

			_signatureCards = new ArrayList<SignatureCard>();
			SmartCardIO io = new SmartCardIO();
			SignatureCardFactory factory = SignatureCardFactory.getInstance();

			for (Entry<CardTerminal, Card> entry : io.getCards().entrySet()) {
				try {
					_signatureCards.add(factory.createSignatureCard(entry.getValue(), entry.getKey()));
				} catch (CardNotSupportedException e) {
					// just log the error - MOCCA tries to connect to all cards and we may have an MSCAPI or PKCS11 also
					// inserted.
					LOG.info(e.getMessage());
				}
			}
		}
		return _signatureCards;
	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {

		List<DSSPrivateKeyEntry> list = getKeysSeveralCards();
		if (list.isEmpty()) {

			throw new DSSException("Cannot retrieve keys from the card!");
		}
		return list;
	}

	private List<DSSPrivateKeyEntry> getKeysSeveralCards() throws DSSException {

		final List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();
		final List<SignatureCard> cardList = getSignatureCards();
		int index = 0;
		for (SignatureCard sc : cardList) {

			try {

				final byte[] data = sc.getCertificate(KeyboxName.SECURE_SIGNATURE_KEYPAIR, callback);
				if (data != null) {

					list.add(new MOCCAPrivateKeyEntry(data, KeyboxName.SECURE_SIGNATURE_KEYPAIR, index, sc.getCard().getATR().getBytes()));
				}
			} catch (Exception e) {

				LOG.error(e.getMessage(), e);
			}
			try {

				final byte[] data = sc.getCertificate(KeyboxName.CERTIFIED_KEYPAIR, callback);
				if (data != null) {

					list.add(new MOCCAPrivateKeyEntry(data, KeyboxName.CERTIFIED_KEYPAIR, index, sc.getCard().getATR().getBytes()));
				}
			} catch (Exception e) {

				LOG.error(e.getMessage(), e);
			}
			index++;
		}
		return list;
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {

		final InputStream inputStream = new ByteArrayInputStream(toBeSigned.getBytes());
		if (!(keyEntry instanceof MOCCAPrivateKeyEntry)) {

			throw new DSSException("Unsupported DSSPrivateKeyEntry instance " + keyEntry.getClass() + " / Must be MOCCAPrivateKeyEntry.");
		}
		final MOCCAPrivateKeyEntry moccaKey = (MOCCAPrivateKeyEntry) keyEntry;
		if (_signatureCards == null) {

			throw new IllegalStateException("The cards have not been initialised");
		}
		// TODO Bob:20130619 This is not completely true, it is true only for the last card. The signing certificate
		// should be checked.
		if (moccaKey.getPos() > (_signatureCards.size() - 1)) {

			throw new IllegalStateException("Card was removed or disconnected " + moccaKey.getPos() + " " + _signatureCards.size());
		}
		final SignatureCard signatureCard = _signatureCards.get(moccaKey.getPos());
		final EncryptionAlgorithm encryptionAlgo = moccaKey.getEncryptionAlgorithm();
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgo, digestAlgorithm);

		LOG.info("MOCCA>>>Signature algorithm: {}", signatureAlgorithm.getJCEId());
		try {

			final KeyboxName keyboxName = moccaKey.getKeyboxName();
			byte[] signedData = signatureCard.createSignature(inputStream, keyboxName, callback, signatureAlgorithm.getXMLId());
			if (EncryptionAlgorithm.ECDSA.equals(encryptionAlgo)) {

				signedData = encode(signedData);
			}

			SignatureValue value = new SignatureValue();
			value.setAlgorithm(signatureAlgorithm);
			value.setValue(signedData);
			return value;

		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf, DSSPrivateKeyEntry keyEntry)
			throws DSSException {
		throw new UnsupportedOperationException();
	}

	/**
	 * The ECDSA_SIG structure consists of two BIGNUMs for the r and s value of a ECDSA signature (see X9.62 or FIPS
	 * 186-2).<br>
	 * This encoding is not implemented at the level of MOCCA!
	 *
	 * @param signedStream
	 * @return
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private static byte[] encode(byte[] signedStream) throws DSSException {

		final int half = signedStream.length / 2;
		final byte[] firstPart = new byte[half];
		final byte[] secondPart = new byte[half];

		System.arraycopy(signedStream, 0, firstPart, 0, half);
		System.arraycopy(signedStream, half, secondPart, 0, half);

		final BigInteger r = new BigInteger(1, firstPart);
		final BigInteger s = new BigInteger(1, secondPart);

		final ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(new ASN1Integer(r));
		v.add(new ASN1Integer(s));

		return DSSASN1Utils.getDEREncoded(new DERSequence(v));
	}

	public int getRetries() {
		return callback.getRetries();
	}

}
