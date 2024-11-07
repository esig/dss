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
package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * Contain util methods for certificate policy identifiers checks
 */
public final class CertificatePolicyIdentifiers {

	private CertificatePolicyIdentifiers() {
	}

	/**
	 * Checks if the certificate if supported by QSCD
	 *
	 * @param certificate {@link CertificateWrapper}
	 * @return TRUE if the certificate is supported by QSCD, FALSE otherwise
	 */
	public static boolean isSupportedByQSCD(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicy.QCP_PUBLIC_WITH_SSCD, CertificatePolicy.QCP_LEGAL_QSCD,
				CertificatePolicy.QCP_NATURAL_QSCD);
	}

	/**
	 * Checks if the certificate is QCP
	 *
	 * @param certificate {@link CertificateWrapper}
	 * @return TRUE if the certificate is QCP, FALSE otherwise
	 */
	public static boolean isQCP(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicy.QCP_PUBLIC);
	}

	/**
	 * Checks if the certificate is QCP with SSCD
	 *
	 * @param certificate {@link CertificateWrapper}
	 * @return TRUE if the certificate is QCP with SSCD, FALSE otherwise
	 */
	public static boolean isQCPPlus(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicy.QCP_PUBLIC_WITH_SSCD);
	}

	/**
	 * Checks if the certificate is legal QCP
	 *
	 * @param certificate {@link CertificateWrapper}
	 * @return TRUE if the certificate is legal QCP, FALSE otherwise
	 */
	public static boolean isLegal(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicy.QCP_LEGAL, CertificatePolicy.QCP_LEGAL_QSCD);
	}

	/**
	 * Checks if the certificate is natural QCP
	 *
	 * @param certificate {@link CertificateWrapper}
	 * @return TRUE if the certificate is natural QCP, FALSE otherwise
	 */
	public static boolean isNatural(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicy.QCP_NATURAL, CertificatePolicy.QCP_NATURAL_QSCD);
	}

	private static boolean hasPolicyIdOIDs(CertificateWrapper certificate, CertificatePolicy... certificatePolicyIds) {
		List<String> policyIds = certificate.getPolicyIds();
		if (Utils.isCollectionNotEmpty(policyIds)) {
			for (CertificatePolicy policyId : certificatePolicyIds) {
				if (policyIds.contains(policyId.getOid())) {
					return true;
				}
			}
		}
		return false;
	}

}
