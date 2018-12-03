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
package eu.europa.esig.dss.pdf;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.pades.validation.PAdESCRLSource;
import eu.europa.esig.dss.pades.validation.PAdESCertificateSource;
import eu.europa.esig.dss.pades.validation.PAdESOCSPSource;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

public class DSSDictionaryCallback {

	private PAdESSignature signature;
	private List<CRLToken> crls;
	private List<OCSPToken> ocsps;
	private Set<CertificateToken> certificates;

	public PAdESSignature getSignature() {
		return signature;
	}

	public void setSignature(PAdESSignature signature) {
		this.signature = signature;
	}

	public Map<Long, byte[]> getStoredCrls() {
		PAdESCRLSource crlSource = (PAdESCRLSource) signature.getCRLSource();
		return crlSource.getCrlMap();
	}

	public Map<Long, BasicOCSPResp> getStoredOcspResps() {
		PAdESOCSPSource ocspSource = (PAdESOCSPSource) signature.getOCSPSource();
		return ocspSource.getOcspMap();
	}

	public Map<Long, CertificateToken> getStoredCertificates() {
		PAdESCertificateSource certSource = signature.getCertificateSource();
		return certSource.getCertificateMap();
	}

	public List<CRLToken> getCrls() {
		return crls;
	}

	public void setCrls(List<CRLToken> crls) {
		this.crls = crls;
	}

	public List<OCSPToken> getOcsps() {
		return ocsps;
	}

	public void setOcsps(List<OCSPToken> ocsps) {
		this.ocsps = ocsps;
	}

	public Set<CertificateToken> getCertificates() {
		return certificates;
	}

	public void setCertificates(Set<CertificateToken> certificates) {
		this.certificates = certificates;
	}

}
