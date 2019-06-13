package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.x509.RevocationOrigin;

public class OCSPResponseIdentifier extends EncapsulatedRevocationTokenIdentifier {

	private static final long serialVersionUID = 6693521503459405568L;
	
	private final BasicOCSPResp basicOCSPResp;
	
	public static OCSPResponseIdentifier build(BasicOCSPResp basicOCSPResp, RevocationOrigin origin) {
		byte[] ocspRespBinary = DSSRevocationUtils.getEncodedFromBasicResp(basicOCSPResp);
		return new OCSPResponseIdentifier(basicOCSPResp, ocspRespBinary, origin);
	}
	
	public static OCSPResponseIdentifier build(BasicOCSPResp basicOCSPResp, List<RevocationOrigin> origins) {
		RevocationOrigin nullOrigin = null;
		OCSPResponseIdentifier ocspResponseIdentifier = build(basicOCSPResp, nullOrigin);
		for (RevocationOrigin origin : origins) {
			ocspResponseIdentifier.addOrigin(origin);
		}
		return ocspResponseIdentifier;
	}
	
	OCSPResponseIdentifier(BasicOCSPResp basicOCSPResp, byte[] encoded, RevocationOrigin origin) {
		super(encoded, origin);
		this.basicOCSPResp = basicOCSPResp;
	}
	
	public BasicOCSPResp getBasicOCSPResp() {
		return basicOCSPResp;
	}
	
}
