package eu.europa.dss.signature.policy.validation.items;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.util.Arrays;

import eu.europa.dss.signature.policy.CertRefReq;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.x509.CertificateToken;

public class CAdESCertRefReqValidator implements ItemValidator {
	
	private CAdESSignature cadesSignature;
	private Set<CertificateToken> fullPath;
	private CertRefReq certificateRefReq;
	private List<ASN1Object> essCertIdIssuers;

	public CAdESCertRefReqValidator(CAdESSignature cadesSignature, CertRefReq certificateRefReq, Set<CertificateToken> fullPath) {
		this.cadesSignature = cadesSignature;
		this.fullPath = fullPath;
		this.certificateRefReq = certificateRefReq;
	}

	/**
	 *    The mandatedCertificateRef identifies:
	 *       *  whether a signer's certificate, or all certificates in the
	 *          certification path to the trust point must be by the signer in
	 *          the *  certificates field of SignedData.
	 * @param certificateRefReq
	 * @param cmsSignedData
	 */
	public boolean validate() {
		if (certificateRefReq == null) {
			certificateRefReq = CertRefReq.signerOnly;
		}
		
 		boolean foundSignerCert = false;
 		X509Certificate signingCert = cadesSignature.getSigningCertificateToken().getCertificate();
 		IssuerSerial signerCertIssuerSerial = new IssuerSerial(GeneralNames.getInstance(signingCert.getIssuerX500Principal().getEncoded()), signingCert.getSerialNumber());
 		essCertIdIssuers = new ArrayList<ASN1Object>();

 		AttributeTable signedAttributes = CMSUtils.getSignedAttributes(cadesSignature.getSignerInformation());
		Attribute attribute = signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
 		if (attribute != null) {
 			final byte[] signerCertHash = cadesSignature.getSigningCertificateToken().getDigest(DigestAlgorithm.SHA1);
 			for(ASN1Encodable enc : attribute.getAttrValues()) {
 				SigningCertificate signingCertificate = SigningCertificate.getInstance(enc);
 				for (ESSCertID certId : signingCertificate.getCerts()) {
 					if (equalsCertificateReference(certId, signerCertIssuerSerial, signerCertHash)) {
 						foundSignerCert = true;
 					} else {
 						if (certificateRefReq == CertRefReq.signerOnly) {
 							return false;
 						}
 						essCertIdIssuers.add(certId);
 					}
 				}
 			}
 		}
 		
 		attribute = signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
 		if (attribute != null) {
 			for(ASN1Encodable enc : attribute.getAttrValues()) {
 				SigningCertificateV2 signingCertificateV2 = SigningCertificateV2.getInstance(enc);
 				for (ESSCertIDv2 certId : signingCertificateV2.getCerts()) {
 					if (equalsCertificateReference(certId, signerCertIssuerSerial, cadesSignature.getSigningCertificateToken())) {
 						foundSignerCert = true;
 					} else {
 						if (certificateRefReq == CertRefReq.signerOnly) {
 							return false;
 						}
 						essCertIdIssuers.add(certId);
 					}
 				}
 			}
 		}
		
		if (!foundSignerCert) {
			return false;
		}
		
		if (certificateRefReq == CertRefReq.signerOnly && containsAdditionalCertRef()) {
			return false;
		}
		
		if (certificateRefReq == CertRefReq.fullPath && !isFullPathPresent(essCertIdIssuers)) {
			return false;
		}
		return true;
	}

	public boolean containsAdditionalCertRef() {
		return !essCertIdIssuers.isEmpty();
	}
	
	private boolean isFullPathPresent(List<ASN1Object> essCertId) {
		if (essCertId.isEmpty()) {
			return false;
		}
		
		for (ASN1Object asn1Object : essCertId) {
			if (!containsReference(asn1Object)) {
				return false;
			}
		}
		return true;
	}
	
	private boolean containsReference(ASN1Object essCertId) {
		for (CertificateToken certificateToken : fullPath) {
			IssuerSerial issuerSerial = new IssuerSerial(
					GeneralNames.getInstance(certificateToken.getIssuerX500Principal().getEncoded()), 
					certificateToken.getSerialNumber());
			if (essCertId instanceof ESSCertID) {
				byte[] hash = certificateToken.getDigest(DigestAlgorithm.SHA1);
				return equalsCertificateReference((ESSCertID) essCertId, issuerSerial, hash);
			} else {
				return equalsCertificateReference((ESSCertIDv2) essCertId, issuerSerial, certificateToken);
			}
		}
		return false;
	}

	private boolean equalsCertificateReference(ESSCertID certId, IssuerSerial certIssuerSerial, byte[] certHash) {
		if (certId.getIssuerSerial().equals(certIssuerSerial)) {
			if (Arrays.areEqual(certHash, certId.getCertHash())) {
				return true;
			}
		}
		return false;
	}
	
	private boolean equalsCertificateReference(ESSCertIDv2 certId, IssuerSerial certIssuerSerial, CertificateToken tk) {
		if (tk == null) {
			return false;
		}
		
		final byte[] certHash = tk.getDigest(DigestAlgorithm.forOID(certId.getHashAlgorithm().getAlgorithm().getId()));
		if (certId.getIssuerSerial().equals(certIssuerSerial)) {
			if (Arrays.areEqual(certHash, certId.getCertHash())) {
				return true;
			}
		}
		return false;
	}
}
