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
package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;

public class ValidationDataForInclusion {
	
	private Set<CertificateToken> certificateTokens;
	private List<CRLToken> crlTokens;
	private List<OCSPToken> ocspTokens;

	void setCertificateTokens(Set<CertificateToken> certificateTokens) {
		this.certificateTokens = certificateTokens;
	}

	void setCrlTokens(List<CRLToken> crlTokens) {
		this.crlTokens = crlTokens;
	}

	void setOcspTokens(List<OCSPToken> ocspTokens) {
		this.ocspTokens = ocspTokens;
	}

	public Set<CertificateToken> getCertificateTokens() {
		if (Utils.isCollectionEmpty(certificateTokens)) {
			certificateTokens = new HashSet<>();
		}
		return certificateTokens;
	}

	public List<CRLToken> getCrlTokens() {
		if (Utils.isCollectionEmpty(crlTokens)) {
			crlTokens = new ArrayList<>();
		}
		return crlTokens;
	}

	public List<OCSPToken> getOcspTokens() {
		if (Utils.isCollectionEmpty(ocspTokens)) {
			ocspTokens = new ArrayList<>();
		}
		return ocspTokens;
	}

	public boolean isEmpty() {
		return Utils.isCollectionEmpty(certificateTokens) && Utils.isCollectionEmpty(crlTokens)
				&& Utils.isCollectionEmpty(ocspTokens);
	}

}
