package eu.europa.dss.signature.policy.validation;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.util.encoders.Hex;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateTestUtils {
	
	public static CertificateToken loadIssuers(File certFile, CertificatePool certPool) throws CertificateException, IOException {
		return loadIssuers(DSSUtils.loadCertificate(certFile), certPool);
	}
	
	public static CertificateToken loadIssuers(CertificateToken certificate, CertificatePool certPool) {
		DataLoader loader = new NativeHTTPDataLoader() {
			@Override
			public byte[] get(String url) {
				if (url.startsWith("ldap")) {
					return null;
				}
				return super.get(url);
			}
		};
		CertificateToken cert = certPool.getInstance(certificate, CertificateSourceType.SIGNATURE);
		return loadIssuers(loader, cert, certPool);
	}
	
	public static CertificateToken loadIssuers(DataLoader loader, CertificateToken certificate, CertificatePool certPool) {
		if (certificate.getIssuerToken() == null) {
			Collection<CertificateToken> issuerCertificates = certPool.get(certificate.getIssuerX500Principal());
			if (issuerCertificates == null || issuerCertificates.isEmpty()) {
				issuerCertificates = DSSUtils.loadIssuerCertificates(certificate, loader);

				if (issuerCertificates != null) {
					for (CertificateToken certificateToken : issuerCertificates) {
						certPool.getInstance(certificateToken, CertificateSourceType.AIA);
					}
				}
			}
			
			if (issuerCertificates != null) {
				for (CertificateToken issuerCertificateToken : issuerCertificates) {
					if (isIssuer(certificate, issuerCertificateToken) && !issuerCertificateToken.isSelfSigned()) {
						loadIssuers(loader, issuerCertificateToken, certPool);
					}
				}
			}
		}
		return certificate;
	}

	private static boolean isIssuer(CertificateToken certificateToken, CertificateToken issuerCertificateToken){
		if (!certificateToken.isSignedBy(issuerCertificateToken)) {
			return false;
		}
		
		String ski = GetSubjectKeyIdentifier(issuerCertificateToken);
		String aki = GetAuthorityKeyIdentifier(certificateToken);
		if (ski != null && aki != null) {
			return ski.equals(aki);
		}
		
		return certificateToken.getIssuerX500Principal().equals(issuerCertificateToken.getSubjectX500Principal());
	}
	
	private static String GetSubjectKeyIdentifier(CertificateToken token) {
		byte[] skiValue = token.getCertificate().getExtensionValue(Extension.subjectKeyIdentifier.getId());
		if (skiValue != null) {
			byte[] ski = ASN1OctetString.getInstance(skiValue).getOctets();
			byte[] id = SubjectKeyIdentifier.getInstance(ski).getKeyIdentifier();
			return Hex.toHexString(id);
		}
		return null;
	}
	
	private static String GetAuthorityKeyIdentifier(CertificateToken token) {
		byte[] akiValue = token.getCertificate().getExtensionValue(Extension.authorityKeyIdentifier.getId());
		if (akiValue != null) {
			AuthorityKeyIdentifier authorityKeyIdentifier;
			byte[] aki = ASN1OctetString.getInstance(akiValue).getOctets();
			authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(aki);
			return Hex.toHexString(authorityKeyIdentifier.getKeyIdentifier());
		}
		return null;
	}
}
