package eu.europa.esig.dss.signature.policy.asn1;

import eu.europa.esig.dss.signature.policy.CertRefReq;

public class ASN1CertRefReqHelper {
	
	public static CertRefReq getInstance(Integer value, CertRefReq defaultValue) {
		if (value != null) {
			for(CertRefReq current : CertRefReq.values()) {
				if (current.ordinal() == value) {
					return current;
				}
			}
		}
		
		if (defaultValue != null) {
			return defaultValue;
		}
		throw new IllegalArgumentException("Invalid value: "+value);
	}
}
