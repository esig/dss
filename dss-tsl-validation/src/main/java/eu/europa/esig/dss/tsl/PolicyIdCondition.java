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
package eu.europa.esig.dss.tsl;

import java.util.List;

import eu.europa.esig.dss.CertificatePolicy;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Checks if a certificate has a specific policy OID.<br>
 * Objects based on this class are instantiated from trusted list or by SignedDocumentValidator for QCP and QCPPlus
 */
public class PolicyIdCondition extends Condition {

	private static final long serialVersionUID = 7590885101177874819L;

	/**
	 * PolicyOid to be checked if present in the certificate's policies
	 */
	private final String policyOid;

	/**
	 * The default constructor for PolicyIdCondition.
	 *
	 * @param policyId
	 *            the policy oid to check
	 */
	public PolicyIdCondition(final String policyId) {
		if (policyId == null) {
			throw new NullPointerException("policyId");
		}
		this.policyOid = policyId;
	}

    /**
     *  Returns the policy OID.
     * 
     *  @return never {@code null}
     */
    public final String getPolicyOid() {
        return policyOid;
    }

	@Override
	public boolean check(final CertificateToken certificateToken) {
		if (certificateToken == null) {
			throw new NullPointerException();
		}
		/**
		 * Certificate policies identifier: 2.5.29.32 (IETF RFC 3280)<br>
		 * Gets all certificate's policies
		 */
		List<CertificatePolicy> contextPolicyIdentifiers = DSSASN1Utils.getCertificatePolicies(certificateToken);
		for (CertificatePolicy certificatePolicy : contextPolicyIdentifiers) {
			if (policyOid.equals(certificatePolicy.getOid())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String toString(String indent) {
		if (indent == null) {
			indent = "";
		}
		StringBuilder builder = new StringBuilder();
		builder.append(indent).append("PolicyIdCondition: ").append(policyOid).append('\n');
		return builder.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}
}
