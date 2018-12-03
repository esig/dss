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
package eu.europa.esig.dss.crl;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509CRLEntry;
import java.text.MessageFormat;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.x509.CertificateToken;

public class CRLUtilsStreamImpl extends AbstractCRLUtils implements ICRLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CRLUtilsStreamImpl.class);

	@Override
	public CRLValidity isValidCRL(InputStream crlStream, CertificateToken issuerToken) throws IOException {

		final CRLValidity crlValidity = new CRLValidity();
		try (ByteArrayOutputStream baos = getDERContent(crlStream)) {

			CRLInfo crlInfos = getCrlInfos(baos);

			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(crlInfos.getCertificateListSignatureAlgorithmOid());

			byte[] digest = recomputeDigest(baos, getMessageDigest(signatureAlgorithm.getDigestAlgorithm()));

			crlValidity.setCrlEncoded(baos.toByteArray());
			crlValidity.setSignatureAlgorithm(signatureAlgorithm);
			crlValidity.setThisUpdate(crlInfos.getThisUpdate());
			crlValidity.setNextUpdate(crlInfos.getNextUpdate());

			checkCriticalExtensions(crlValidity, crlInfos.getCriticalExtensions().keySet(),
					crlInfos.getCriticalExtension(Extension.issuingDistributionPoint.getId()));

			extractExpiredCertsOnCRL(crlValidity, crlInfos.getNonCriticalExtension(Extension.expiredCertsOnCRL.getId()));

			final X500Principal x509CRLIssuerX500Principal = crlInfos.getIssuer();
			final X500Principal issuerTokenSubjectX500Principal = issuerToken.getSubjectX500Principal();
			if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {
				crlValidity.setIssuerX509PrincipalMatches(true);
			}

			checkSignatureValue(crlValidity, crlInfos.getSignatureValue(), digest, issuerToken);
		}
		return crlValidity;
	}

	private MessageDigest getMessageDigest(DigestAlgorithm digestAlgorithm) {
		try {
			return MessageDigest.getInstance(digestAlgorithm.getOid(), BouncyCastleProvider.PROVIDER_NAME);
		} catch (GeneralSecurityException e) {
			throw new DSSException("Cannot generate a MessageDigest", e);
		}
	}

	@Override
	public X509CRLEntry getRevocationInfo(CRLValidity crlValidity, BigInteger serialNumber) {
		CRLParser parser = new CRLParser();
		X509CRLEntry crlEntry = null;
		try (InputStream is = crlValidity.getCrlInputStream()) {
			crlEntry = parser.retrieveRevocationInfo(is, serialNumber);
		} catch (IOException e) {
			LOG.error("Unable to retrieve the revocation status", e);
		}
		return crlEntry;
	}

	private void checkSignatureValue(CRLValidity crlValidity, byte[] signatureValue, byte[] expectedDigest, CertificateToken signer) {
		byte[] extractedDigest = null;
		try {
			extractedDigest = getSignedDigest(signatureValue, signer);
		} catch (GeneralSecurityException | IOException e) {
			crlValidity.setSignatureInvalidityReason(e.getClass().getSimpleName() + " - " + e.getMessage());
			return;
		}

		if (Arrays.equals(expectedDigest, extractedDigest)) {
			crlValidity.setSignatureIntact(true);
			crlValidity.setIssuerToken(signer);
			crlValidity.setCrlSignKeyUsage(signer.checkKeyUsage(KeyUsageBit.crlSign));
		} else {
			String extractedDigestString = extractedDigest == null ? "" : Hex.toHexString(extractedDigest);
			String expectedDigestString = expectedDigest == null ? "" : Hex.toHexString(expectedDigest);
			String message = MessageFormat.format("Signed digest ''{0}'' and computed digest ''{1}'' don''t match",
					new Object[] { extractedDigestString, expectedDigestString });
			crlValidity.setSignatureInvalidityReason(message);
			LOG.warn(message);
		}
	}

	private byte[] recomputeDigest(ByteArrayOutputStream baos, MessageDigest messageDigest) throws IOException {
		try (InputStream is = new ByteArrayInputStream(baos.toByteArray()); DigestInputStream dis = new DigestInputStream(is, messageDigest)) {
			CRLParser parser = new CRLParser();
			parser.processDigest(dis);
			return dis.getMessageDigest().digest();
		}
	}

	private CRLInfo getCrlInfos(ByteArrayOutputStream baos) throws IOException {
		try (InputStream is = new ByteArrayInputStream(baos.toByteArray()); BufferedInputStream bis = new BufferedInputStream(is)) {
			CRLParser parser = new CRLParser();
			return parser.retrieveInfo(bis);
		}
	}

	private byte[] getSignedDigest(byte[] signatureValue, CertificateToken signer) throws GeneralSecurityException, IOException {
		PublicKey publicKey = signer.getPublicKey();
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] decrypted = cipher.doFinal(signatureValue);

		try (ASN1InputStream inputDecrypted = new ASN1InputStream(decrypted)) {
			ASN1Sequence seqDecrypt = (ASN1Sequence) inputDecrypted.readObject();
			DigestInfo digestInfo = new DigestInfo(seqDecrypt);
			return digestInfo.getDigest();
		}
	}

	@SuppressWarnings("resource")
	private ByteArrayOutputStream getDERContent(InputStream crlStream) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int first = crlStream.read();
		baos.write(first);

		byte[] buffer = new byte[4096];
		int n;
		while (-1 != (n = crlStream.read(buffer))) {
			baos.write(buffer, 0, n);
		}

		if (isPemEncoded(first)) {
			baos = PemToDerConverter.convert(baos);
		} else if (!isDerEncoded(first)) {
			throw new DSSException("Unsupported CRL");
		}
		return baos;
	}

	private boolean isPemEncoded(int first) {
		return '-' == (byte) first;
	}

	private boolean isDerEncoded(int first) {
		return (BERTags.SEQUENCE | BERTags.CONSTRUCTED) == first;
	}

}
