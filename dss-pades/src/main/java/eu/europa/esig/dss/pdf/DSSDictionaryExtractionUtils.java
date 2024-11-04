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

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Contains utils for a DSS dictionary content extraction
 */
public class DSSDictionaryExtractionUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSDictionaryExtractionUtils.class);

	/**
	 * Empty constructor
	 */
	private DSSDictionaryExtractionUtils() {
		// empty
	}

	/**
	 * Extract certificate object map
	 *
	 * @param dict {@link PdfDict}
	 * @param dictionaryName {@link String} name of the dictionary
	 * @param arrayName {@link String} containing the certificates
	 * @return a map of certificate objects
	 */
	public static Map<PdfObjectKey, CertificateToken> getCertsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		Map<PdfObjectKey, CertificateToken> certMap = new LinkedHashMap<>(); // use LinkedHashMap to preserve the order
		final PdfArray certsArray = dict.getAsArray(arrayName);
		if (certsArray != null) {
			LOG.debug("There are {} certificates in the '{}' dictionary", certsArray.size(), dictionaryName);
			for (int ii = 0; ii < certsArray.size(); ii++) {
				try {
					final PdfObjectKey objectKey = certsArray.getObjectKey(ii);
					if (!certMap.containsKey(objectKey)) {
						certMap.put(objectKey, DSSUtils.loadCertificate(certsArray.getStreamBytes(ii)));
					}
				} catch (Exception e) {
					LOG.debug("Unable to read Cert '{}' from the '{}' dictionary : {}", ii, dictionaryName, e.getMessage(), e);
				}
			}
		} else {
			LOG.debug("No Certs found in the '{}' dictionary", dictionaryName);
		}
		return certMap;
	}

	/**
	 * Extract CRL object map
	 *
	 * @param dict {@link PdfDict}
	 * @param dictionaryName {@link String} name of the dictionary
	 * @param arrayName {@link String} containing the CRLs
	 * @return a map of CRL objects
	 */
	public static Map<PdfObjectKey, CRLBinary> getCRLsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		Map<PdfObjectKey, CRLBinary> crlMap = new LinkedHashMap<>();
		final PdfArray crlArray = dict.getAsArray(arrayName);
		if (crlArray != null) {
			LOG.debug("There are {} CRLs in the '{}' dictionary", crlArray.size(), dictionaryName);
			for (int ii = 0; ii < crlArray.size(); ii++) {
				try {
					PdfObjectKey objectKey = crlArray.getObjectKey(ii);
					if (!crlMap.containsKey(objectKey)) {
						crlMap.put(objectKey, CRLUtils.buildCRLBinary(crlArray.getStreamBytes(ii)));
					}
				} catch (Exception e) {
					LOG.debug("Unable to read CRL '{}' from the '{}' dictionary : {}", ii, dictionaryName, e.getMessage(), e);
				}
			}
		} else {
			LOG.debug("No CRLs found in the '{}' dictionary", dictionaryName);
		}
		return crlMap;
	}

	/**
	 * Extract OCSP object map
	 *
	 * @param dict {@link PdfDict}
	 * @param dictionaryName {@link String} name of the dictionary
	 * @param arrayName {@link String} containing the OCSPs
	 * @return a map of OCSP objects
	 */
	public static Map<PdfObjectKey, OCSPResponseBinary> getOCSPsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		Map<PdfObjectKey, OCSPResponseBinary> ocspMap = new LinkedHashMap<>();
		PdfArray ocspArray = dict.getAsArray(arrayName);
		if (ocspArray != null) {
			LOG.debug("There are {} OCSPs in the '{}' dictionary", ocspArray.size(), dictionaryName);
			for (int ii = 0; ii < ocspArray.size(); ii++) {
				try {
					final PdfObjectKey objectKey = ocspArray.getObjectKey(ii);
					if (!ocspMap.containsKey(objectKey)) {
						final OCSPResp ocspResp = new OCSPResp(ocspArray.getStreamBytes(ii));
						final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
						ocspMap.put(objectKey, OCSPResponseBinary.build(basicOCSPResp));
					}
				} catch (Exception e) {
					LOG.debug("Unable to read OCSP '{}' from the '{}' dictionary : {}", ii, dictionaryName, e.getMessage(), e);
				}
			}
		} else {
			LOG.debug("No OCSPs found in the '{}' dictionary", dictionaryName);
		}
		return ocspMap;
	}

	/**
	 * This method returns a value of 'TU' field when present
	 *
	 * @param dict {@link PdfDict} to get 'TU' time from
	 * @return {@link Date}
	 */
	public static Date getDictionaryCreationTime(PdfDict dict) {
		return dict.getDateValue(PAdESConstants.TU_DICTIONARY_NAME_VRI);
	}

	/**
	 * This method returns timestamp binaries extracted from 'TS' field, when present
	 *
	 * @param dict {@link PdfDict} to get 'TS' timestamp from
	 * @return byte array representing a timestamp when present
	 */
	public static byte[] getTimestampBinaries(PdfDict dict) {
		PdfDict tsDict = dict.getAsDict(PAdESConstants.TS_DICTIONARY_NAME_VRI);
		if (tsDict != null) {
			try {
				return tsDict.getStreamBytes();
			} catch (IOException e) {
				LOG.warn("Unable to extract 'TS' stream : {}", e.getMessage());
			}
		}
		return null;
	}

}
