package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;

public class ValidationDataForInclusion {
	
	private Set<CertificateToken> certificateTokens;
	private List<CRLToken> crlTokens;
	private List<OCSPToken> ocspTokens;

	void setCertificateTokens(Set<CertificateToken> certificateTokens) {
		this.certificateTokens = certificateTokens;
	}

	void setCrlTokens(List<CRLToken> crlTokens) {
		this.crlTokens = crlTokens;
	}

	void setOcspTokens(List<OCSPToken> ocspTokens) {
		this.ocspTokens = ocspTokens;
	}

	public Set<CertificateToken> getCertificateTokens() {
		if (Utils.isCollectionEmpty(certificateTokens)) {
			certificateTokens = new HashSet<>();
		}
		return certificateTokens;
	}

	public List<CRLToken> getCrlTokens() {
		if (Utils.isCollectionEmpty(crlTokens)) {
			crlTokens = new ArrayList<>();
		}
		return crlTokens;
	}

	public List<OCSPToken> getOcspTokens() {
		if (Utils.isCollectionEmpty(ocspTokens)) {
			ocspTokens = new ArrayList<>();
		}
		return ocspTokens;
	}

}
