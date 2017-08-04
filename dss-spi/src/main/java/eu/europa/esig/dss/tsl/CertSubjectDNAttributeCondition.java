package eu.europa.esig.dss.tsl;

import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * CertSubjectDNAttribute
 * 
 * Presence: This field is optional.
 * 
 * Description: It provides a non empty set of OIDs. Each OID maps to a possible attribute in the Subject DN of
 * the certificate. The criteria is matched if all OID refers to an attribute present in the DN.
 * 
 * Format: A non-empty sequence of OIDs representing Directory attributes, whose meaning respect the
 * description above. For the formal definition see CertSubjectDNAttribute element in the
 * schema referenced by clause C.2 (point 3).
 *
 */
public class CertSubjectDNAttributeCondition extends Condition {

	private final List<String> subjectAttributeOids;

	public CertSubjectDNAttributeCondition(List<String> oids) {
		this.subjectAttributeOids = oids;
	}

	@Override
	public boolean check(CertificateToken certificateToken) {
		X500Principal subjectX500Principal = certificateToken.getSubjectX500Principal();
		if (Utils.isCollectionNotEmpty(subjectAttributeOids)) {
			for (String oid : subjectAttributeOids) {
				String attribute = DSSASN1Utils.extractAttributeFromX500Principal(new ASN1ObjectIdentifier(oid), subjectX500Principal);
				if (Utils.isStringEmpty(attribute)) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public String toString(String indent) {
		return "CertSubjectDNAttributeCondition : " + subjectAttributeOids;
	}

	@Override
	public String toString() {
		return toString("");
	}

}
