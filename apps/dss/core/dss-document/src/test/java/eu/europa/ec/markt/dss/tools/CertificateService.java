package eu.europa.ec.markt.dss.tools;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

public class CertificateService {

	private static final BouncyCastleProvider SECURITY_PROVIDER = new BouncyCastleProvider();

	static {
		Security.addProvider(SECURITY_PROVIDER);
	}

	public KeyPair generateKeyPair(final EncryptionAlgorithm algorithm) throws GeneralSecurityException {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm.getName());
		keyGenerator.initialize(1024);
		return keyGenerator.generateKeyPair();
	}

	public DSSPrivateKeyEntry generateCertificateChain(final SignatureAlgorithm algorithm) throws Exception {
		DSSPrivateKeyEntry rootEntry = generateSelfSignedCertificate(algorithm);
		X500Name rootName = new JcaX509CertificateHolder(rootEntry.getCertificate()).getSubject();

		KeyPair childKeyPair = generateKeyPair(algorithm.getEncryptionAlgorithm());
		X500Name childSubject = new X500Name("CN=SignerChildOfRootFake,O=DSS-test");
		X509Certificate child = generateCertificate(algorithm, childSubject, rootName, rootEntry.getPrivateKey(), childKeyPair.getPublic());
		X509Certificate[] chain = createChildCertificateChain(rootEntry);

		return new MockPrivateKeyEntry(algorithm.getEncryptionAlgorithm(), child, chain, childKeyPair.getPrivate());
	}

	public DSSPrivateKeyEntry generateSelfSignedCertificate(final SignatureAlgorithm algorithm) throws Exception {
		KeyPair keyPair = generateKeyPair(algorithm.getEncryptionAlgorithm());
		X500Name issuer = new X500Name("CN=RootIssuerSelfSignedFake,O=DSS-test");
		X500Name subject = new X500Name("CN=RootSubjectSelfSignedFake,O=DSS-test");

		X509Certificate certificate = generateCertificate(algorithm, subject, issuer, keyPair.getPrivate(), keyPair.getPublic());

		return new MockPrivateKeyEntry(algorithm.getEncryptionAlgorithm(), certificate, keyPair.getPrivate());
	}

	public X509Certificate generateCertificate(final SignatureAlgorithm algorithm, final X500Name subject, final X500Name issuer,
			final PrivateKey issuerPrivateKey, final PublicKey publicKey) throws Exception {

		final Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000); // yesterday
		final Date notAfter = new Date(System.currentTimeMillis() + 10 * 24 * 60 * 60 * 1000); // 10d

		// generate certificate
		final SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

		final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, new BigInteger("" + new Random().nextInt(10)
				+ System.currentTimeMillis()), notBefore, notAfter, subject, keyInfo);

		final KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature);
		certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

		// Sign the new certificate with the private key of the trusted third
		final ContentSigner signer = new JcaContentSignerBuilder(algorithm.getJCEId()).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
				issuerPrivateKey);
		final X509CertificateHolder holder = certBuilder.build(signer);

		final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(
				new ByteArrayInputStream(holder.getEncoded()));

		return cert;
	}

	private X509Certificate[] createChildCertificateChain(DSSPrivateKeyEntry rootEntry) {
		List<X509Certificate> chainList = new ArrayList<X509Certificate>();
		chainList.add(rootEntry.getCertificate());
		X509Certificate[] rootChain = rootEntry.getCertificateChain();
		if (rootChain != null && rootChain.length > 0) {
			for (X509Certificate certChainItem : rootChain) {
				chainList.add(certChainItem);
			}
		}

		X509Certificate[] chain = chainList.toArray(new X509Certificate[chainList.size()]);
		return chain;
	}

}
