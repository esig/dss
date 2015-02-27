package eu.europa.ec.markt.dss.service;

import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

public class CRLGenerator {

	private static final BouncyCastleProvider SECURITY_PROVIDER = new BouncyCastleProvider();

	static {
		Security.addProvider(SECURITY_PROVIDER);
	}

	public X509CRL generateCRL(X509Certificate certToRevoke, DSSPrivateKeyEntry issuerEntry, Date dateOfRevoke, int reason) throws Exception {

		Date now = new Date();
		X500Name x500nameIssuer = new JcaX509CertificateHolder(issuerEntry.getCertificate().getCertificate()).getSubject();
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(x500nameIssuer, now);

		crlGen.setNextUpdate(new Date(now.getTime() + (60 * 60 * 1000)));

		crlGen.addCRLEntry(certToRevoke.getSerialNumber(), dateOfRevoke, reason);

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

		crlGen.addExtension(Extension.authorityKeyIdentifier, false,
				extUtils.createAuthorityKeyIdentifier(issuerEntry.getCertificate().getPublicKey()));

		X509CRLHolder crlHolder = crlGen.build(new JcaContentSignerBuilder(issuerEntry.getCertificate().getCertificate().getSigAlgName()).setProvider(
				BouncyCastleProvider.PROVIDER_NAME).build(issuerEntry.getPrivateKey()));

		JcaX509CRLConverter converter = new JcaX509CRLConverter();
		return converter.getCRL(crlHolder);
	}

}
