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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package eu.europa.esig.dss.test.gen;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateService {

	private static final BouncyCastleProvider SECURITY_PROVIDER = new BouncyCastleProvider();

	private static final int MAX = Integer.MAX_VALUE;

	static {
		Security.addProvider(SECURITY_PROVIDER);
	}

	// Annotation for error_probe
	@SuppressWarnings("InsecureCryptoUsage")
	public KeyPair generateKeyPair(final EncryptionAlgorithm algorithm) throws GeneralSecurityException {
		if (algorithm == EncryptionAlgorithm.ECDSA) {
			return generateECDSAKeyPair();
		} else if (algorithm == EncryptionAlgorithm.RSA) {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", SECURITY_PROVIDER);
			keyGenerator.initialize(2048);
			return keyGenerator.generateKeyPair();
		} else if (algorithm == EncryptionAlgorithm.DSA) {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DSA", SECURITY_PROVIDER);
			keyGenerator.initialize(1024);
			return keyGenerator.generateKeyPair();
		}
		throw new DSSException("Unknown algo : " + algorithm);
	}

	private KeyPair generateECDSAKeyPair() throws GeneralSecurityException {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", SECURITY_PROVIDER);
		generator.initialize(ecSpec, new SecureRandom());
		return generator.generateKeyPair();
	}

	public MockPrivateKeyEntry generateCertificateChain(final SignatureAlgorithm algorithm, final MockPrivateKeyEntry rootEntry, Date notBefore, Date notAfter)
			throws Exception {
		X500Name rootName = new JcaX509CertificateHolder(rootEntry.getCertificate().getCertificate()).getSubject();
		KeyPair childKeyPair = generateKeyPair(algorithm.getEncryptionAlgorithm());

		X500Name childSubject = new X500Name("CN=SignerFake,O=DSS-test");
		CertificateToken child = generateRootCertificateWithCrl(algorithm, childSubject, rootName, rootEntry.getPrivateKey(), childKeyPair.getPublic(),
				notBefore, notAfter);
		CertificateToken[] chain = createChildCertificateChain(rootEntry);

		return new MockPrivateKeyEntry(algorithm.getEncryptionAlgorithm(), child, chain, childKeyPair.getPrivate());
	}

	public MockPrivateKeyEntry generateCertificateChain(final SignatureAlgorithm algorithm, boolean rootCrl) throws Exception {
		MockPrivateKeyEntry rootEntry = generateSelfSignedCertificate(algorithm, rootCrl);

		Date notBefore = new Date(System.currentTimeMillis() - (24 * 60 * 60 * 1000)); // yesterday
		Date notAfter = new Date(System.currentTimeMillis() + MAX); // 1000d

		return generateCertificateChain(algorithm, rootEntry, notBefore, notAfter);
	}

	public MockPrivateKeyEntry generateCertificateChain(final SignatureAlgorithm algorithm) throws Exception {
		return generateCertificateChain(algorithm, true);
	}

	public MockPrivateKeyEntry generateCertificateChain(final SignatureAlgorithm algorithm, MockPrivateKeyEntry rootEntry) throws Exception {
		Date notBefore = new Date(System.currentTimeMillis() - (24 * 60 * 60 * 1000)); // yesterday
		Date notAfter = new Date(System.currentTimeMillis() + MAX); // 1000d

		return generateCertificateChain(algorithm, rootEntry, notBefore, notAfter);
	}

	public MockPrivateKeyEntry generateExpiredCertificateChain(final SignatureAlgorithm algorithm, boolean rootCrl) throws Exception {
		MockPrivateKeyEntry rootEntry = generateSelfSignedCertificate(algorithm, rootCrl);

		Date notBefore = new Date(System.currentTimeMillis() - (10 * 24 * 60 * 60 * 1000)); // -10d
		Date notAfter = new Date(System.currentTimeMillis() - (24 * 60 * 60 * 1000)); // yesterday

		return generateCertificateChain(algorithm, rootEntry, notBefore, notAfter);
	}

	public MockPrivateKeyEntry generateSelfSignedCertificate(final SignatureAlgorithm algorithm, boolean rootCrl) throws Exception {
		KeyPair keyPair = generateKeyPair(algorithm.getEncryptionAlgorithm());
		X500Name issuer = new X500Name("CN=RootSelfSignedFake,O=DSS-test");

		Date notBefore = new Date(System.currentTimeMillis() - (24 * 60 * 60 * 1000)); // yesterday
		Date notAfter = new Date(System.currentTimeMillis() + MAX); // 1000d

		CertificateToken certificate = null;
		if (rootCrl) {
			certificate = generateRootCertificateWithCrl(algorithm, issuer, issuer, keyPair.getPrivate(), keyPair.getPublic(), notBefore, notAfter);
		} else {
			certificate = generateRootCertificateWithoutCrl(algorithm, issuer, issuer, keyPair.getPrivate(), keyPair.getPublic(), notBefore, notAfter);
		}

		return new MockPrivateKeyEntry(algorithm.getEncryptionAlgorithm(), certificate, keyPair.getPrivate());
	}

	public MockPrivateKeyEntry generateTspCertificate(final SignatureAlgorithm algorithm) throws Exception {
		KeyPair keyPair = generateKeyPair(algorithm.getEncryptionAlgorithm());
		X500Name issuer = new X500Name("CN=RootIssuerTSPFake,O=DSS-test");
		X500Name subject = new X500Name("CN=RootSubjectTSP,O=DSS-test");

		final Date notBefore = new Date(System.currentTimeMillis() - (24 * 60 * 60 * 1000)); // yesterday
		final Date notAfter = new Date(System.currentTimeMillis() + MAX); // 1000d

		// generate certificate
		CertificateToken cert = generateTspCertificate(algorithm, keyPair, issuer, subject, notBefore, notAfter);
		return new MockPrivateKeyEntry(algorithm.getEncryptionAlgorithm(), cert, keyPair.getPrivate());
	}

	/**
	 * Generate a CertificateToken suitable for a TSA
	 *
	 * @param algorithm
	 * @param keyPair
	 * @param issuer
	 * @param subject
	 * @param notBefore
	 * @param notAfter
	 * @return
	 * @throws CertIOException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public CertificateToken generateTspCertificate(final SignatureAlgorithm algorithm, KeyPair keyPair, X500Name issuer, X500Name subject, final Date notBefore,
			final Date notAfter) throws CertIOException, OperatorCreationException, CertificateException, IOException {
		final SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

		final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer,
				new BigInteger("" + new Random().nextInt(10) + System.currentTimeMillis()), notBefore, notAfter, subject, keyInfo);

		certBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

		final ContentSigner signer = new JcaContentSignerBuilder(algorithm.getJCEId()).setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.build(keyPair.getPrivate());
		final X509CertificateHolder holder = certBuilder.build(signer);

		final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
				.generateCertificate(new ByteArrayInputStream(holder.getEncoded()));

		return new CertificateToken(cert);
	}

	public CertificateToken generateRootCertificateWithCrl(SignatureAlgorithm algorithm, X500Name subject, X500Name issuer, PrivateKey issuerPrivateKey,
			PublicKey publicKey, Date notBefore, Date notAfter) throws Exception {

		// generate certificate
		final SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

		final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer,
				new BigInteger("" + new Random().nextInt(10) + System.currentTimeMillis()), notBefore, notAfter, subject, keyInfo);

		certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

		// Sign the new certificate with the private key of the trusted third
		final ContentSigner signer = new JcaContentSignerBuilder(algorithm.getJCEId()).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerPrivateKey);
		final X509CertificateHolder holder = certBuilder.build(signer);

		final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
				.generateCertificate(new ByteArrayInputStream(holder.getEncoded()));

		return new CertificateToken(cert);
	}

	public CertificateToken generateRootCertificateWithoutCrl(SignatureAlgorithm algorithm, X500Name subject, X500Name issuer, PrivateKey issuerPrivateKey,
			PublicKey publicKey, Date notBefore, Date notAfter) throws Exception {

		// generate certificate
		final SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

		final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer,
				new BigInteger("" + new Random().nextInt(10) + System.currentTimeMillis()), notBefore, notAfter, subject, keyInfo);

		certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

		// Sign the new certificate with the private key of the trusted third
		final ContentSigner signer = new JcaContentSignerBuilder(algorithm.getJCEId()).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerPrivateKey);
		final X509CertificateHolder holder = certBuilder.build(signer);

		final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509")
				.generateCertificate(new ByteArrayInputStream(holder.getEncoded()));

		return new CertificateToken(cert);
	}

	private CertificateToken[] createChildCertificateChain(DSSPrivateKeyEntry rootEntry) {
		List<CertificateToken> chainList = new ArrayList<CertificateToken>();
		chainList.add(rootEntry.getCertificate());
		CertificateToken[] rootChain = rootEntry.getCertificateChain();
		if ((rootChain != null) && (rootChain.length > 0)) {
			for (CertificateToken certChainItem : rootChain) {
				chainList.add(certChainItem);
			}
		}

		CertificateToken[] chain = chainList.toArray(new CertificateToken[chainList.size()]);
		return chain;
	}

}
