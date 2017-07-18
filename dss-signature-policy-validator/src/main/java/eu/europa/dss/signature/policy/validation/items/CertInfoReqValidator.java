package eu.europa.dss.signature.policy.validation.items;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import eu.europa.dss.signature.policy.CertInfoReq;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertInfoReqValidator {

	private CertInfoReq mandatedCertificateInfo;
	private AdvancedSignature adesSignature;
	private Set<CertificateToken> fullPath;

	public CertInfoReqValidator(CertInfoReq mandatedCertificateInfo, AdvancedSignature adesSignature,
			Set<CertificateToken> fullPath) {
		super();
		this.mandatedCertificateInfo = mandatedCertificateInfo;
		this.adesSignature = adesSignature;
		this.fullPath = fullPath;
	}

	public boolean validate() {
		if (mandatedCertificateInfo == null || mandatedCertificateInfo == CertInfoReq.none) {
			return true;
		}
		
		Collection<CertificateToken> certificates = adesSignature.getCertificateSource().getKeyInfoCertificates();
		if (adesSignature.getSigningCertificateToken() == null || !certificates.contains(adesSignature.getSigningCertificateToken())) {
			return false;
		} else if (mandatedCertificateInfo == CertInfoReq.fullPath && !containsSignerFullChain(adesSignature.getCertificateSource().getKeyInfoCertificates())) {
			return false;
		}
		return true;
	}

	private boolean containsSignerFullChain(List<CertificateToken> certificates) {
		if (fullPath == null || fullPath.isEmpty() || (fullPath.size() == 1 && fullPath.contains(adesSignature.getSigningCertificateToken()))) {
			// If it was not possible to build the certification path, any check should fail
			return false;
		}
		
		if (certificates == null || certificates.size() <= fullPath.size()) {
			return false;
		}
		
		for (CertificateToken cert : fullPath) {
			if (!certificates.contains(cert)) {
				return false;
			}
		}
		
		return true;
	}
}
