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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;

import java.util.Map;

/**
 * An abstract implementation of {@code PdfDssDict}
 */
public abstract class AbstractPdfDssDict implements PdfDssDict {

	private static final long serialVersionUID = 625347967057384829L;

	/** The map of CRL objects */
	private final Map<PdfObjectKey, CRLBinary> crlMap;

	/** The map of OCSP objects */
	private final Map<PdfObjectKey, OCSPResponseBinary> ocspMap;

	/** The map of certificate objects */
	private final Map<PdfObjectKey, CertificateToken> certMap;

	/**
	 * Default constructor
	 *
	 * @param dssDictionary {@link PdfDict}
	 */
	protected AbstractPdfDssDict(PdfDict dssDictionary) {
		this.certMap = DSSDictionaryExtractionUtils.getCertsFromArray(dssDictionary, getDictionaryName(), getCertArrayDictionaryName());
		this.ocspMap = DSSDictionaryExtractionUtils.getOCSPsFromArray(dssDictionary, getDictionaryName(), getOCSPArrayDictionaryName());
		this.crlMap = DSSDictionaryExtractionUtils.getCRLsFromArray(dssDictionary, getDictionaryName(), getCRLArrayDictionaryName());
	}

	/**
	 * Gets the dictionary name (DSS or VRI)
	 *
	 * @return {@link String}
	 */
	protected abstract String getDictionaryName();

	/**
	 * Gets the certificate array dictionary name
	 *
	 * @return {@link String}
	 */
	protected abstract String getCertArrayDictionaryName();

	/**
	 * Gets the CRL array dictionary name
	 *
	 * @return {@link String}
	 */
	protected abstract String getCRLArrayDictionaryName();

	/**
	 * Gets the OCSP array dictionary name
	 *
	 * @return {@link String}
	 */
	protected abstract String getOCSPArrayDictionaryName();

	@Override
	public Map<PdfObjectKey, CRLBinary> getCRLs() {
		return crlMap;
	}

	@Override
	public Map<PdfObjectKey, OCSPResponseBinary> getOCSPs() {
		return ocspMap;
	}

	@Override
	public Map<PdfObjectKey, CertificateToken> getCERTs() {
		return certMap;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((certMap == null) ? 0 : certMap.hashCode());
		result = prime * result + ((crlMap == null) ? 0 : crlMap.hashCode());
		result = prime * result + ((ocspMap == null) ? 0 : ocspMap.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AbstractPdfDssDict other = (AbstractPdfDssDict) obj;
		if (certMap == null) {
			if (other.certMap != null) {
				return false;
			}
		} else if (!certMap.equals(other.certMap)) {
			return false;
		}
		if (crlMap == null) {
			if (other.crlMap != null) {
				return false;
			}
		} else if (!crlMap.equals(other.crlMap)) {
			return false;
		}
		if (ocspMap == null) {
			if (other.ocspMap != null) {
				return false;
			}
		} else if (!ocspMap.equals(other.ocspMap)) {
			return false;
		}
		return true;
	}


}
