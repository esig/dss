package eu.europa.ec.markt.dss.tools;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorException;
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

	public DSSPrivateKeyEntry generateCertificate(final SignatureAlgorithm algorithm) throws GeneralSecurityException, OperatorException {

		final Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000); // yesterday
		final Date notAfter = new Date(System.currentTimeMillis() + 10 * 24 * 60 * 60 * 1000); // 10d

		final X500Name issuer = new X500Name("CN=FakeIssuer");
		final X500Name subject = new X500Name("CN=FakeSubject");
		final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

		final KeyPair keyPair = generateKeyPair(algorithm.getEncryptionAlgorithm());
		final byte[] encoded = keyPair.getPublic().getEncoded();
		final SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));
		X509v1CertificateBuilder certificateBuilder = new X509v1CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKeyInfo);
		ContentSigner signer = new JcaContentSignerBuilder(algorithm.getJCEId()).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
				keyPair.getPrivate());
		X509CertificateHolder certificateHolder = certificateBuilder.build(signer);
		final X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
				certificateHolder);

		return new MockPrivateKeyEntry(algorithm.getEncryptionAlgorithm(), certificate, keyPair.getPrivate());
	}

}
