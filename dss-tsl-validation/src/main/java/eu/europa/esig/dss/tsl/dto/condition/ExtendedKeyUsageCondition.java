/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.dto.condition;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Collections;
import java.util.List;

import static java.util.Collections.unmodifiableList;

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
public class ExtendedKeyUsageCondition implements Condition {

	private static final long serialVersionUID = -5969735320082024885L;

	/** List of extended key usages to check */
	private final List<String> extendedKeyUsageOids;

	/**
	 * Default constructor
	 *
	 * @param oids a list of extended key usages to check
	 */
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
            Collections.emptyList() :
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
