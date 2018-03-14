/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.validation.items;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.signature.policy.CertInfoReq;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertInfoReqValidator implements ItemValidator {

	private CertInfoReq mandatedCertificateInfo;
	private AdvancedSignature adesSignature;
	private Set<CertificateToken> fullPath;

	public CertInfoReqValidator(CertInfoReq mandatedCertificateInfo, AdvancedSignature adesSignature,
			Set<CertificateToken> fullPath) {
		super();
		this.mandatedCertificateInfo = mandatedCertificateInfo;
		this.adesSignature = adesSignature;
		this.fullPath = fullPath;
	}

	public boolean validate() {
		if (mandatedCertificateInfo == null || mandatedCertificateInfo == CertInfoReq.none) {
			return true;
		}
		
		Collection<CertificateToken> certificates = adesSignature.getCertificateSource().getKeyInfoCertificates();
		if (adesSignature.getSigningCertificateToken() == null || !certificates.contains(adesSignature.getSigningCertificateToken())) {
			return false;
		} else if (mandatedCertificateInfo == CertInfoReq.fullPath && !containsSignerFullChain(adesSignature.getCertificateSource().getKeyInfoCertificates())) {
			return false;
		}
		return true;
	}

	private boolean containsSignerFullChain(List<CertificateToken> certificates) {
		if (fullPath == null || fullPath.isEmpty() || (fullPath.size() == 1 && fullPath.contains(adesSignature.getSigningCertificateToken()))) {
			// If it was not possible to build the certification path, any check should fail
			return false;
		}
		
		if (certificates == null || certificates.size() <= fullPath.size()) {
			return false;
		}
		
		for (CertificateToken cert : fullPath) {
			if (!certificates.contains(cert)) {
				return false;
			}
		}
		
		return true;
	}
	
	@Override
	public String getErrorDetail() {
		return null;
	}
}
