package eu.europa.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;

import eu.europa.dss.signature.policy.EnuRevReq;

/**
 *                                               }
 * @author davyd.santos
 *
 */
public class ASN1EnuRevReqHelper {

	public static EnuRevReq getInstance(ASN1Encodable as) {
		ASN1Enumerated enu = ASN1Enumerated.getInstance(as);
		return getInstance(as == null? null: enu.getValue().intValue(), null);
	}

	public static EnuRevReq getInstance(Integer value, EnuRevReq defaultValue) {
		if (value != null) {
			for(EnuRevReq current : EnuRevReq.values()) {
				if (current.ordinal() == value) {
					return current;
				}
			}
		}
		
		if (defaultValue != null) {
			return defaultValue;
		}
		throw new IllegalArgumentException("Invalid value: " + value);
	}
}