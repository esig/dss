/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.condition;

import java.security.cert.X509Certificate;
import java.util.List;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * Checks if a certificate has a specific policy OID.<br>
 * Objects based on this class are instantiated from trusted list or by SignedDocumentValidator for QCP and QCPPlus
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (Mon, 06 Jun 2011) $
 */

public class PolicyIdCondition extends Condition {

	private static final long serialVersionUID = 7590885101177874819L;

	/**
	 * PolicyOid to be checked if present in the certificate's policies
	 */
	final private String policyOid;

	/**
	 * The default constructor for PolicyIdCondition.
	 *
	 * @param policyId
	 */
	public PolicyIdCondition(final String policyId) {

		if (policyId == null) {
			throw new DSSNullException(StrictMath.class, "policyId");
		}
		this.policyOid = policyId;
	}

	/**
	 * @return the policyOid
	 */
	public String getPolicyOid() {

		return policyOid;
	}

	/**
	 * Checks the condition for the given certificate.
	 *
	 * @param certificateToken certificate to be checked
	 * @return
	 */
	@Override
	public boolean check(final CertificateToken certificateToken) {

		if (certificateToken == null) {
			throw new DSSNullException(X509Certificate.class);
		}
		/**
		 * Certificate policies identifier: 2.5.29.32 (IETF RFC 3280)<br>
		 * Gets all certificate's policies
		 */
		List<String> contextPolicyIdentifiers = certificateToken.getPolicyIdentifiers();
		return contextPolicyIdentifiers.contains(policyOid);
	}

	@Override
	public String toString(String indent) {

		try {

			if (indent == null) {
				indent = "";
			}
			StringBuilder builder = new StringBuilder();
			builder.append(indent).append("PolicyIdCondition: ").append(policyOid).append('\n');
			return builder.toString();
		} catch (Exception e) {

			return e.toString();
		}
	}

	@Override
	public String toString() {
		return toString("");
	}
}
