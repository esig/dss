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
package eu.europa.esig.dss.crl;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

class CRLInfo {

	private Integer version;
	private String certificateListSignatureAlgorithmOid;
	private byte[] certificateListSignatureAlgorithmParams;
	private X500Principal issuer;
	private Date thisUpdate;
	private Date nextUpdate;
	private String tbsSignatureAlgorithmOid;
	private byte[] signatureValue;
	private Map<String, byte[]> criticalExtensions = new HashMap<String, byte[]>();
	private Map<String, byte[]> nonCriticalExtensions = new HashMap<String, byte[]>();

	public Integer getVersion() {
		return version;
	}

	void setVersion(Integer version) {
		this.version = version;
	}

	public String getCertificateListSignatureAlgorithmOid() {
		return certificateListSignatureAlgorithmOid;
	}

	void setCertificateListSignatureAlgorithmOid(String certificateListSignatureAlgorithmOid) {
		this.certificateListSignatureAlgorithmOid = certificateListSignatureAlgorithmOid;
	}

	byte[] getCertificateListSignatureAlgorithmParams() {
		return certificateListSignatureAlgorithmParams;
	}

	void setCertificateListSignatureAlgorithmParams(byte[] certificateListSignatureAlgorithmParams) {
		this.certificateListSignatureAlgorithmParams = certificateListSignatureAlgorithmParams;
	}

	public X500Principal getIssuer() {
		return issuer;
	}

	void setIssuer(X500Principal issuer) {
		this.issuer = issuer;
	}

	public Date getThisUpdate() {
		return thisUpdate;
	}

	void setThisUpdate(Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}

	public Date getNextUpdate() {
		return nextUpdate;
	}

	void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	public String getTbsSignatureAlgorithmOid() {
		return tbsSignatureAlgorithmOid;
	}

	void setTbsSignatureAlgorithmOid(String tbsSignatureAlgorithmOid) {
		this.tbsSignatureAlgorithmOid = tbsSignatureAlgorithmOid;
	}

	public byte[] getSignatureValue() {
		return signatureValue;
	}

	void setSignatureValue(byte[] signatureValue) {
		this.signatureValue = signatureValue;
	}

	void addCriticalExtension(String oid, byte[] content) {
		this.criticalExtensions.put(oid, content);
	}

	public byte[] getCriticalExtension(String oid) {
		return criticalExtensions.get(oid);
	}

	public Map<String, byte[]> getCriticalExtensions() {
		return criticalExtensions;
	}

	void addNonCriticalExtension(String oid, byte[] content) {
		this.nonCriticalExtensions.put(oid, content);
	}

	public byte[] getNonCriticalExtension(String oid) {
		return nonCriticalExtensions.get(oid);
	}

	public Map<String, byte[]> getNonCriticalExtensions() {
		return nonCriticalExtensions;
	}

}
