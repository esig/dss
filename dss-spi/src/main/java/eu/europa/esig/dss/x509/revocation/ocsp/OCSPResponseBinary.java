package eu.europa.esig.dss.x509.revocation.ocsp;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;

public class OCSPResponseBinary extends EncapsulatedRevocationTokenIdentifier {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPResponseBinary.class);

	private static final long serialVersionUID = 6693521503459405568L;
	
	private transient final BasicOCSPResp basicOCSPResp;
	
	// specifies origin of the OCSP Response from SignedData.CRLs element
	// Note: Used in CAdES only!
	private transient ASN1ObjectIdentifier asn1ObjectIdentifier;
	
	public static OCSPResponseBinary build(BasicOCSPResp basicOCSPResp) {
		byte[] ocspRespBinary = DSSRevocationUtils.getEncodedFromBasicResp(basicOCSPResp);
		return new OCSPResponseBinary(basicOCSPResp, ocspRespBinary);
	}
	
	OCSPResponseBinary(BasicOCSPResp basicOCSPResp, byte[] encoded) {
		super(encoded);
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
