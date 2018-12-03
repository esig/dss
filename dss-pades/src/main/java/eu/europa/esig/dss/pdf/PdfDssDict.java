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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is a representation of a DSS (Document Security Store) Dictionary embedded in a PDF file.
 * The dictionary is unique in a PDF file and can contain : VRI dictionary, certificates (Certs), OCSP responses (OCSPs)
 * and CRLs.
 * This dictionary is filled in PAdES-BASELINE-LT extension process.
 */
public class PdfDssDict {

	private static final Logger LOG = LoggerFactory.getLogger(PdfDssDict.class);

	/* Maps with object number + value */
	private Map<Long, byte[]> crlMap = new HashMap<Long, byte[]>();
	private Map<Long, BasicOCSPResp> ocspMap = new HashMap<Long, BasicOCSPResp>();
	private Map<Long, CertificateToken> certMap = new HashMap<Long, CertificateToken>();

	public static PdfDssDict extract(PdfDict documentDict) {
		if (documentDict != null) {
			final PdfDict dssCatalog = documentDict.getAsDict(PAdESConstants.DSS_DICTIONARY_NAME);
			if (dssCatalog != null) {
				return new PdfDssDict(dssCatalog);
			}
		}
		LOG.debug("No DSS dictionary found");
		return null;
	}

	private PdfDssDict(PdfDict dssDictionary) {
		readVRI(dssDictionary);
		readCerts(dssDictionary);
		readCrls(dssDictionary);
		readOcsps(dssDictionary);
	}

	private void readVRI(PdfDict dssDictionary) {
		PdfDict vriDict = dssDictionary.getAsDict(PAdESConstants.VRI_DICTIONARY_NAME);
		if (vriDict != null) {
			LOG.debug("There is a VRI dictionary in DSS dictionary");
			try {
				String[] names = vriDict.list();
				if (Utils.isArrayNotEmpty(names)) {
					for (String name : names) {
						extractCertsFromArray(vriDict.getAsDict(name), PAdESConstants.VRI_DICTIONARY_NAME + "/" + name,
								PAdESConstants.CERT_ARRAY_NAME_VRI);
						extractOCSPsFromArray(vriDict.getAsDict(name), PAdESConstants.VRI_DICTIONARY_NAME + "/" + name,
								PAdESConstants.OCSP_ARRAY_NAME_VRI);
						extractCRLsFromArray(vriDict.getAsDict(name), PAdESConstants.VRI_DICTIONARY_NAME + "/" + name,
								PAdESConstants.CRL_ARRAY_NAME_VRI);
					}
				}
			} catch (Exception e) {
				LOG.debug("Unable to analyse VRI dictionary : {}", e.getMessage());
			}
		} else {
			LOG.debug("No VRI dictionary found in DSS dictionary");
		}
	}

	private void readCerts(PdfDict dssDictionary) {
		extractCertsFromArray(dssDictionary, PAdESConstants.DSS_DICTIONARY_NAME, PAdESConstants.CERT_ARRAY_NAME_DSS);
	}

	private void readOcsps(PdfDict dssDictionary) {
		extractOCSPsFromArray(dssDictionary, PAdESConstants.DSS_DICTIONARY_NAME, PAdESConstants.OCSP_ARRAY_NAME_DSS);
	}

	private void readCrls(PdfDict dssDictionary) {
		extractCRLsFromArray(dssDictionary, PAdESConstants.DSS_DICTIONARY_NAME, PAdESConstants.CRL_ARRAY_NAME_DSS);
	}

	private void extractCRLsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		final PdfArray crlArray = dict.getAsArray(arrayName);
		if (crlArray != null) {
			LOG.debug("There are {} CRLs in {} dictionary", crlArray.size(), dictionaryName);
			for (int ii = 0; ii < crlArray.size(); ii++) {
				try {
					crlMap.put(crlArray.getObjectNumber(ii), crlArray.getBytes(ii));
				} catch (Exception e) {
					LOG.debug("Unable to read CRL " + ii + " from " + dictionaryName + " dictionary : " + e.getMessage(), e);
				}
			}
		} else {
			LOG.debug("No CRLs found in {} dictionary", dictionaryName);
		}
	}

	private void extractCertsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		final PdfArray certsArray = dict.getAsArray(arrayName);
		if (certsArray != null) {
			LOG.debug("There are {} certificates in {} dictionary", certsArray.size(), dictionaryName);
			for (int ii = 0; ii < certsArray.size(); ii++) {
				try {
					final byte[] stream = certsArray.getBytes(ii);
					final CertificateToken cert = DSSUtils.loadCertificate(stream);
					certMap.put(certsArray.getObjectNumber(ii), cert);
				} catch (Exception e) {
					LOG.debug("Unable to read Cert " + ii + " from " + dictionaryName + " dictionary : " + e.getMessage(), e);
				}
			}
		} else {
			LOG.debug("No Certs found in {} dictionary", dictionaryName);
		}
	}

	private void extractOCSPsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		PdfArray ocspArray = dict.getAsArray(arrayName);
		if (ocspArray != null) {
			LOG.debug("There are {} OCSPs in {} dictionary", ocspArray.size(), dictionaryName);
			for (int ii = 0; ii < ocspArray.size(); ii++) {
				try {
					final byte[] stream = ocspArray.getBytes(ii);
					final OCSPResp ocspResp = new OCSPResp(stream);
					final BasicOCSPResp responseObject = (BasicOCSPResp) ocspResp.getResponseObject();
					ocspMap.put(ocspArray.getObjectNumber(ii), responseObject);
				} catch (Exception e) {
					LOG.debug("Unable to read OCSP " + ii + " from " + dictionaryName + " dictionary : " + e.getMessage(), e);
				}
			}
		} else {
			LOG.debug("No OCSPs found in {} dictionary", dictionaryName);
		}
	}

	public Map<Long, byte[]> getCrlMap() {
		return Collections.unmodifiableMap(crlMap);
	}

	public Map<Long, BasicOCSPResp> getOcspMap() {
		return Collections.unmodifiableMap(ocspMap);
	}

	public Map<Long, CertificateToken> getCertMap() {
		return Collections.unmodifiableMap(certMap);
	}

}
