/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.dto.condition;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.model.tsl.Condition;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Collections;
import java.util.List;

import static java.util.Collections.unmodifiableList;

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
public class CertSubjectDNAttributeCondition implements Condition {

	private static final long serialVersionUID = 5941353274395443267L;

	/** List of DN attribute OIDs to be checked against the certificate’s subject DN */
	private final List<String> subjectAttributeOids;

	/**
	 * Default constructor
	 *
	 * @param oids a list of DN attribute OIDs to be checked
	 */
	public CertSubjectDNAttributeCondition(List<String> oids) {
		this.subjectAttributeOids = oids;
	}

    /**
     * Returns the list of DN attribute OIDs to be checked
     * against the certificate’s subject DN.
     * 
     * @return an unmodifiable list, possibly empty; never {@code null}
     */
    public final List<String> getAttributeOids() {
        return subjectAttributeOids == null ?
            Collections.emptyList() :
            unmodifiableList(subjectAttributeOids);
    }

	@Override
	public boolean check(CertificateToken certificateToken) {
		if (Utils.isCollectionNotEmpty(subjectAttributeOids)) {
			X500PrincipalHelper subject = certificateToken.getSubject();
			for (String oid : subjectAttributeOids) {
				String attribute = DSSASN1Utils.extractAttributeFromX500Principal(new ASN1ObjectIdentifier(oid),
						subject);
				if (Utils.isStringEmpty(attribute)) {
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
		builder.append(indent).append("CertSubjectDNAttributeCondition: ").append(subjectAttributeOids).append('\n');
		return builder.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}

}
