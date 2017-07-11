package eu.europa.dss.signature.policy.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;

import eu.europa.dss.signature.policy.HowCertAttribute;

/**
 * @author davyd.santos
 *
 */
public class ASN1HowCertAttributeHelper {
	
	public static HowCertAttribute getInstance(ASN1Encodable as) {
		ASN1Enumerated enu = ASN1Enumerated.getInstance(as);
		return getInstance(as == null? null: enu.getValue().intValue(), null);
	}
	
	public static HowCertAttribute getInstance(Integer value, HowCertAttribute defaultValue) {
		if (value != null) {
			for(HowCertAttribute v : HowCertAttribute.values()) {
				if (v.ordinal() == value) {
					return v;
				}
			}
		}
		
		if (defaultValue != null) {
			return defaultValue;
		}
		throw new IllegalArgumentException("Invalid value: " + value);
	}
}
