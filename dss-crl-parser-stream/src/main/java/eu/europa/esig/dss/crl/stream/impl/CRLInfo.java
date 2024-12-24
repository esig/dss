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
package eu.europa.esig.dss.crl.stream.impl;

import javax.security.auth.x500.X500Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * This class contains the information extracted from a CRL
 */
class CRLInfo {

	/** TBSCertList version */
	private Integer version;

	/** The certificates SignatureAlgorithm OID */
	private String certificateListSignatureAlgorithmOid;

	/** The certificates SignatureAlgorithm parameters */
	private byte[] certificateListSignatureAlgorithmParams;

	/** X500Principal of the issuer certificate */
	private X500Principal issuer;

	/** The 'thisUpdate' date value */
	private Date thisUpdate;

	/** The 'nextUpdate' date value */
	private Date nextUpdate;

	/** The TBS SignatureAlgorithm OID */
	private String tbsSignatureAlgorithmOid;

	/** The signatureValue */
	private byte[] signatureValue;

	/** A map between critical extensions' OIDs and their contents */
	private Map<String, byte[]> criticalExtensions = new HashMap<>();

	/** A map between non-critical extensions' OIDs and their contents */
	private Map<String, byte[]> nonCriticalExtensions = new HashMap<>();

	/**
	 * Gets TBSCertList version
	 *
	 * @return {@link Integer} TBSCertList version
	 */
	public Integer getVersion() {
		return version;
	}

	/**
	 * Sets TBSCertList version
	 *
	 * @param version {@link Integer} TBSCertList version
	 */
	void setVersion(Integer version) {
		this.version = version;
	}

	/**
	 * Gets certificates SignatureAlgorithm OID
	 *
	 * @return {@link String}
	 */
	public String getCertificateListSignatureAlgorithmOid() {
		return certificateListSignatureAlgorithmOid;
	}

	/**
	 * Sets certificates SignatureAlgorithm OID
	 *
	 * @param certificateListSignatureAlgorithmOid {@link String}
	 */
	void setCertificateListSignatureAlgorithmOid(String certificateListSignatureAlgorithmOid) {
		this.certificateListSignatureAlgorithmOid = certificateListSignatureAlgorithmOid;
	}

	/**
	 * Gets certificates SignatureAlgorithm parameters
	 *
	 * @return certificates SignatureAlgorithm parameters
	 */
	byte[] getCertificateListSignatureAlgorithmParams() {
		return certificateListSignatureAlgorithmParams;
	}

	/**
	 * Sets certificates SignatureAlgorithm parameters
	 *
	 * @param certificateListSignatureAlgorithmParams certificates SignatureAlgorithm parameters
	 */
	void setCertificateListSignatureAlgorithmParams(byte[] certificateListSignatureAlgorithmParams) {
		this.certificateListSignatureAlgorithmParams = certificateListSignatureAlgorithmParams;
	}

	/**
	 * Gets issuer certificate's {@code X500Principal}
	 *
	 * @return {@link X500Principal}
	 */
	public X500Principal getIssuer() {
		return issuer;
	}

	/**
	 * Sets issuer certificate's {@code X500Principal}
	 *
	 * @param issuer {@link X500Principal}
	 */
	void setIssuer(X500Principal issuer) {
		this.issuer = issuer;
	}

	/**
	 * Gets the 'thisUpdate' field Date
	 *
	 * @return {@link Date}
	 */
	public Date getThisUpdate() {
		return thisUpdate;
	}

	/**
	 * Sets the 'thisUpdate' field Date
	 *
	 * @param thisUpdate {@link Date}
	 */
	void setThisUpdate(Date thisUpdate) {
		this.thisUpdate = thisUpdate;
	}

	/**
	 * Gets the 'nextUpdate' field Date
	 *
	 * @return {@link Date}
	 */
	public Date getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * Sets the 'nextUpdate' field Date
	 *
	 * @param nextUpdate {@link Date}
	 */
	void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	/**
	 * Gets TBS SignatureAlgorithm OID
	 *
	 * @return {@link String}
	 */
	public String getTbsSignatureAlgorithmOid() {
		return tbsSignatureAlgorithmOid;
	}

	/**
	 * Sets TBS SignatureAlgorithm OID
	 *
	 * @param tbsSignatureAlgorithmOid {@link String}
	 */
	void setTbsSignatureAlgorithmOid(String tbsSignatureAlgorithmOid) {
		this.tbsSignatureAlgorithmOid = tbsSignatureAlgorithmOid;
	}

	/**
	 * Gets the CRL's signatureValue
	 *
	 * @return signatureValue binaries
	 */
	public byte[] getSignatureValue() {
		return signatureValue;
	}

	/**
	 * Sets the CRL's signatureValue
	 *
	 * @param signatureValue binaries
	 */
	void setSignatureValue(byte[] signatureValue) {
		this.signatureValue = signatureValue;
	}

	/**
	 * Adds a critical extension
	 *
	 * @param oid {@link String} oid of the extension
	 * @param content byte array
	 */
	void addCriticalExtension(String oid, byte[] content) {
		this.criticalExtensions.put(oid, content);
	}

	/**
	 * Gets a critical extension content by its OID
	 *
	 * @param oid {@link String} oid of a critical extension to get content for
	 * @return critical extension content
	 */
	public byte[] getCriticalExtension(String oid) {
		return criticalExtensions.get(oid);
	}

	/**
	 * Returns a map of critical extensions' OIDs and corresponding content
	 *
	 * @return {@link Map} of critical extensions
	 */
	public Map<String, byte[]> getCriticalExtensions() {
		return criticalExtensions;
	}

	/**
	 * Adds a non-critical extension
	 *
	 * @param oid {@link String} oid of the extension
	 * @param content byte array
	 */
	void addNonCriticalExtension(String oid, byte[] content) {
		this.nonCriticalExtensions.put(oid, content);
	}

	/**
	 * Gets a non-critical extension content by its OID
	 *
	 * @param oid {@link String} oid of a critical extension to get content for
	 * @return critical extension content
	 */
	public byte[] getNonCriticalExtension(String oid) {
		return nonCriticalExtensions.get(oid);
	}

	/**
	 * Returns a map of non-critical extensions' OIDs and corresponding content
	 *
	 * @return {@link Map} of critical extensions
	 */
	public Map<String, byte[]> getNonCriticalExtensions() {
		return nonCriticalExtensions;
	}

}
