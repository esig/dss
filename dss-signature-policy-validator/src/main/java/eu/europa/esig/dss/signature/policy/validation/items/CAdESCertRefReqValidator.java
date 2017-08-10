package eu.europa.esig.dss.signature.policy.validation.items;

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
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.util.Arrays;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.policy.CertRefReq;
import eu.europa.esig.dss.x509.CertificateToken;

public class CAdESCertRefReqValidator implements ItemValidator {
	
	private CAdESSignature cadesSignature;
	private Set<CertificateToken> fullPath;
	private CertRefReq certificateRefReq;
	private List<ASN1Object> essCertIdIssuers;

	public CAdESCertRefReqValidator(CertRefReq certificateRefReq, CAdESSignature cadesSignature, Set<CertificateToken> fullPath) {
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
 		CertificateToken signingCertificateToken = cadesSignature.getSigningCertificateToken();
 		if (signingCertificateToken == null) {
 			return false;
 		}

 		if (certificateRefReq == null) {
 			certificateRefReq = CertRefReq.signerOnly;
 		}
 		
		IssuerSerial signerCertIssuerSerial = DSSASN1Utils.getIssuerSerial(signingCertificateToken);
 		essCertIdIssuers = new ArrayList<ASN1Object>();

 		AttributeTable signedAttributes = CMSUtils.getSignedAttributes(cadesSignature.getSignerInformation());
		Attribute attribute = signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
 		if (attribute != null) {
 			final byte[] signerCertHash = signingCertificateToken.getDigest(DigestAlgorithm.SHA1);
 			for(ASN1Encodable enc : attribute.getAttrValues()) {
 				SigningCertificate signingCertificate = SigningCertificate.getInstance(enc);
 				for (ESSCertID certId : signingCertificate.getCerts()) {
 					if (equalsCertificateReference(certId, signerCertIssuerSerial, signerCertHash)) {
 						if (certificateRefReq == CertRefReq.signerOnly) {
 							return true;
 						}
 					}
 					essCertIdIssuers.add(certId);
 				}
 			}
 		}
 		
 		attribute = signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
 		if (attribute != null) {
 			for(ASN1Encodable enc : attribute.getAttrValues()) {
 				SigningCertificateV2 signingCertificateV2 = SigningCertificateV2.getInstance(enc);
 				for (ESSCertIDv2 certId : signingCertificateV2.getCerts()) {
 					if (equalsCertificateReference(certId, signerCertIssuerSerial, signingCertificateToken)) {
 						if (certificateRefReq == CertRefReq.signerOnly) {
 							return true;
 						}
 					}
 					essCertIdIssuers.add(certId);
 				}
 			}
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
		if (fullPath == null || fullPath.isEmpty()) {
			return false;
		}
		
		for (CertificateToken certificateToken : fullPath) {
			if (!containsReference(essCertId, certificateToken)) {
				return false;
			}
		}
		return true;
	}
	
	private boolean containsReference(List<ASN1Object> essCertIds, CertificateToken certificateToken) {
		for (ASN1Object essCertId : essCertIds) {
			IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(certificateToken);
			if (essCertId instanceof ESSCertID) {
				byte[] hash = certificateToken.getDigest(DigestAlgorithm.SHA1);
				if (equalsCertificateReference((ESSCertID) essCertId, issuerSerial, hash)) {
					return true;
				}
			} else {
				if (equalsCertificateReference((ESSCertIDv2) essCertId, issuerSerial, certificateToken)) {
					return true;
				}
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
	
	@Override
	public String getErrorDetail() {
		return null;
	}
}
