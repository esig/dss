package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.Objects;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.x509.RevocationOrigin;

public class OCSPResponse {
	
	private final BasicOCSPResp basicOCSPResp;
	private final RevocationOrigin revocationOrigin;
	
	public OCSPResponse(BasicOCSPResp basicOCSPResp, RevocationOrigin revocationOrigin) {
		this.basicOCSPResp = basicOCSPResp;
		this.revocationOrigin = revocationOrigin;
	}
	
	public BasicOCSPResp getBasicOCSPResp() {
		return basicOCSPResp;
	}
	
	public RevocationOrigin getOrigin() {
		return revocationOrigin;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof OCSPResponse)) {
			return false;
		}
		OCSPResponse o = (OCSPResponse) obj;
		return basicOCSPResp.equals(o.getBasicOCSPResp()) && revocationOrigin.equals(o.getOrigin());
	}

	@Override
	public int hashCode() {
		return Objects.hash(basicOCSPResp, revocationOrigin.name());
	}

}
