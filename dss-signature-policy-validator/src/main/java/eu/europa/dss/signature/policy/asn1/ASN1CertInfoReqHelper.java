package eu.europa.dss.signature.policy.asn1;

import eu.europa.dss.signature.policy.CertInfoReq;

public class ASN1CertInfoReqHelper {
	
	public static CertInfoReq getInstance(Integer value, CertInfoReq defaultValue) {
		if (value != null) {
			for(CertInfoReq current : CertInfoReq.values()) {
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
