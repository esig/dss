package eu.europa.esig.dss.tsl;

import java.util.Collections;
import java.util.List;
import static java.util.Collections.unmodifiableList;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * ExtendedKeyUsage
 * 
 * Presence: This field is optional.
 * 
 * Description: It provides a non empty list of key purposes values to match with the correspondent KeyPurposes
 * present in the ExtendedKeyUsage certificate Extension. The assertion is verified if the
 * ExtendedKeyUsage Extension is present in the certificate and all key purposes provided are
 * present in the certificate ExtendedKeyUsage Extension.
 * 
 * Format: A non-empty sequence of KeyPurposes, whose semantic shall be as defined in X.509 [1] for the
 * ExtendedKeyUsage Extension. For the formal definition see ExtendedKeyUsage element in
 * the schema referenced by clause C.2 (point 3).
 *
 */
public class ExtendedKeyUsageCondition extends Condition {

	private static final long serialVersionUID = -5969735320082024885L;

	private final List<String> extendedKeyUsageOids;

	public ExtendedKeyUsageCondition(List<String> oids) {
		this.extendedKeyUsageOids = oids;
	}

    /**
     * Returns the list key purpose IDs to be be checked against the
     * certificate’s extended key usage extension.
     * 
     * @return an unmodifiable list, possibly empty; never {@code null}
     */
    public final List<String> getKeyPurposeIds() {
        return extendedKeyUsageOids == null ?
            Collections.<String> emptyList() :
            unmodifiableList(extendedKeyUsageOids);
    }
    
	@Override
	public boolean check(CertificateToken certificateToken) {
		if (Utils.isCollectionNotEmpty(extendedKeyUsageOids)) {
			for (String oid : extendedKeyUsageOids) {
				if (!DSSASN1Utils.isExtendedKeyUsagePresent(certificateToken, new ASN1ObjectIdentifier(oid))) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public String toString(String indent) {
		if (indent == null) {
			indent = "";
		}
		StringBuilder builder = new StringBuilder();
		builder.append(indent).append("ExtendedKeyUsageCondition: ").append(extendedKeyUsageOids).append('\n');
		return builder.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}

}
