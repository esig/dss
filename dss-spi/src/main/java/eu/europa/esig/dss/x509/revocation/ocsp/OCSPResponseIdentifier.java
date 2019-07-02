package eu.europa.esig.dss.x509.revocation.ocsp;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.x509.RevocationOrigin;

public class OCSPResponseIdentifier extends EncapsulatedRevocationTokenIdentifier {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPResponseIdentifier.class);

	private static final long serialVersionUID = 6693521503459405568L;
	
	private final BasicOCSPResp basicOCSPResp;
	
	// specifies origin of the OCSP Response from SignedData.CRLs element
	// Note: Used in CAdES only!
	private ASN1ObjectIdentifier asn1ObjectIdentifier;
	
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
	
	public byte[] getBasicOCSPRespContent() {
		try {
			return basicOCSPResp.getEncoded();
		} catch (IOException e) {
			LOG.warn("Cannot get content bytes from BasicOCSPResponse of OCSPResponseIdentifier with id [{}]. Reason: [{}]", asXmlId(), e.getMessage());
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}
	}
	
	public ASN1ObjectIdentifier getAsn1ObjectIdentifier() {
		return asn1ObjectIdentifier;
	}
	
	public void setAsn1ObjectIdentifier(ASN1ObjectIdentifier asn1ObjectIdentifier) {
		this.asn1ObjectIdentifier = asn1ObjectIdentifier;
	} 

}
