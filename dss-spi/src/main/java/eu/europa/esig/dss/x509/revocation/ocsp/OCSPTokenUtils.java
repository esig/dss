package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

public class OCSPTokenUtils {
	
	public static void checkTokenValidity(OCSPToken ocspToken, CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		CertificatePool validationCertPool = new CertificatePool();
		validationCertPool.getInstance(certificateToken, CertificateSourceType.OCSP_RESPONSE);
		validationCertPool.getInstance(issuerCertificateToken, CertificateSourceType.OCSP_RESPONSE);
		checkTokenValidity(ocspToken, validationCertPool);
	}
	
	public static void checkTokenValidity(OCSPToken ocspToken, CertificatePool validationCertPool) {
		final boolean found = extractSigningCertificateFromResponse(ocspToken, validationCertPool);
		if (!found) {
			extractSigningCertificateFormResponderId(ocspToken, validationCertPool);
		}
	}
	
	private static boolean extractSigningCertificateFromResponse(OCSPToken ocspToken, CertificatePool validationCertPool) {
		BasicOCSPResp basicOCSPResp = ocspToken.getBasicOCSPResp();
		if (basicOCSPResp != null) {
			for (final X509CertificateHolder x509CertificateHolder : basicOCSPResp.getCerts()) {
				CertificateToken certificateToken = DSSASN1Utils.getCertificate(x509CertificateHolder);
				CertificateToken certToken = validationCertPool.getInstance(certificateToken, CertificateSourceType.OCSP_RESPONSE);
				if (ocspToken.isSignedBy(certToken)) {
					ocspToken.setIssuerX500Principal(certToken.getSubjectX500Principal());
					return true;
				}
			}
		}
		return false;
	}

	private static void extractSigningCertificateFormResponderId(OCSPToken ocspToken, CertificatePool validationCertPool) {
		BasicOCSPResp basicOCSPResp = ocspToken.getBasicOCSPResp();
		if (basicOCSPResp != null) {
			final RespID responderId = basicOCSPResp.getResponderId();
			final ResponderID responderIdAsASN1Object = responderId.toASN1Primitive();
			final DERTaggedObject derTaggedObject = (DERTaggedObject) responderIdAsASN1Object.toASN1Primitive();
			if (1 == derTaggedObject.getTagNo()) {
				final ASN1Primitive derObject = derTaggedObject.getObject();
				final byte[] derEncoded = DSSASN1Utils.getDEREncoded(derObject);
				final X500Principal x500Principal_ = new X500Principal(derEncoded);
				final X500Principal x500Principal = DSSUtils.getNormalizedX500Principal(x500Principal_);
				final List<CertificateToken> certificateTokens = validationCertPool.get(x500Principal);
				for (final CertificateToken issuerCertificateToken : certificateTokens) {
					if (ocspToken.isSignedBy(issuerCertificateToken)) {
						ocspToken.setIssuerX500Principal(issuerCertificateToken.getSubjectX500Principal());
						break;
					}
				}
			} else if (2 == derTaggedObject.getTagNo()) {
				final ASN1OctetString hashOctetString = (ASN1OctetString) derTaggedObject.getObject();
				final byte[] expectedHash = hashOctetString.getOctets();
				final List<CertificateToken> certificateTokens = validationCertPool.getBySki(expectedHash);
				for (CertificateToken issuerCertificateToken : certificateTokens) {
					if (ocspToken.isSignedBy(issuerCertificateToken)) {
						ocspToken.setIssuerX500Principal(issuerCertificateToken.getSubjectX500Principal());
						break;
					}
				}
			} else {
				throw new DSSException("Unsupported tag No " + derTaggedObject.getTagNo());
			}
		}
	}


}
