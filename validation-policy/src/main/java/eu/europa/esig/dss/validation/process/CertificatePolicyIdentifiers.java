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
package eu.europa.esig.dss.validation.process;

import java.util.List;

import eu.europa.esig.dss.CertificatePolicyOids;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public final class CertificatePolicyIdentifiers {

	private CertificatePolicyIdentifiers() {
	}

	public static boolean isSupportedByQSCD(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_PUBLIC_WITH_SSCD, CertificatePolicyOids.QCP_LEGAL_QSCD,
				CertificatePolicyOids.QCP_NATURAL_QSCD);
	}

	public static boolean isQCP(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_PUBLIC);
	}

	public static boolean isQCPPlus(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_PUBLIC_WITH_SSCD);
	}

	public static boolean isLegal(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_LEGAL, CertificatePolicyOids.QCP_LEGAL_QSCD);
	}

	public static boolean isNatural(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_NATURAL, CertificatePolicyOids.QCP_NATURAL_QSCD);
	}

	private static boolean hasPolicyIdOIDs(CertificateWrapper certificate, CertificatePolicyOids... certificatePolicyIds) {
		List<String> policyIds = certificate.getPolicyIds();
		if (Utils.isCollectionNotEmpty(policyIds)) {
			for (CertificatePolicyOids policyId : certificatePolicyIds) {
				if (policyIds.contains(policyId.getOid())) {
					return true;
				}
			}
		}
		return false;
	}

}
