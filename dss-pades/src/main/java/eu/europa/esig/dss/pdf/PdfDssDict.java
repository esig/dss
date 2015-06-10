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

import java.security.cert.X509CRL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is a representation of a DSS (Document Security Store) Dictionary embedded in a PDF file.
 * The dictionary is unique in a PDF file and can contain : VRI dictionary, certificates (Certs), OCSP responses (OCSPs) and CRLs.
 * This dictionary is filled in PAdES-BASELINE-LT extension process.
 */
public class PdfDssDict {

	private static final Logger logger = LoggerFactory.getLogger(PdfDssDict.class);

	private static final String DSS_DICTIONARY_NAME = "DSS";
	private static final String CERT_ARRAY_NAME_DSS = "Certs";
	private static final String OCSP_ARRAY_NAME_DSS = "OCSPs";
	private static final String CRL_ARRAY_NAME_DSS = "CRLs";

	private static final String VRI_DICTIONARY_NAME = "VRI";
	private static final String CERT_ARRAY_NAME_VRI = "Cert";
	private static final String OCSP_ARRAY_NAME_VRI = "OCSP";
	private static final String CRL_ARRAY_NAME_VRI = "CRL";

	private Set<X509CRL> crlList = new HashSet<X509CRL>();

	private Set<BasicOCSPResp> ocspList = new HashSet<BasicOCSPResp>();

	private Set<CertificateToken> certList = new HashSet<CertificateToken>();

	public static PdfDssDict build(PdfDict documentDict) {
		if (documentDict != null) {
			final PdfDict dssCatalog = documentDict.getAsDict(DSS_DICTIONARY_NAME);
			if (dssCatalog != null) {
				return new PdfDssDict(dssCatalog);
			}
		}
		logger.debug("No DSS dictionary found");
		return null;
	}

	private PdfDssDict(PdfDict dssDictionary) {
		readVRI(dssDictionary);
		readCerts(dssDictionary);
		readCrls(dssDictionary);
		readOcsps(dssDictionary);
	}

	private void readVRI(PdfDict dssDictionary) {
		PdfDict vriDict = dssDictionary.getAsDict(VRI_DICTIONARY_NAME);
		if (vriDict != null) {
			logger.debug("There is a VRI dictionary in DSS dictionary");
			try {
				String[] names = vriDict.list();
				if (ArrayUtils.isNotEmpty(names)) {
					for (String name : names) {
						extractCertsFromArray(vriDict.getAsDict(name), VRI_DICTIONARY_NAME + "/" + name, CERT_ARRAY_NAME_VRI);
						extractOCSPsFromArray(vriDict.getAsDict(name), VRI_DICTIONARY_NAME + "/" + name, OCSP_ARRAY_NAME_VRI);
						extractCRLsFromArray(vriDict.getAsDict(name), VRI_DICTIONARY_NAME + "/" + name, CRL_ARRAY_NAME_VRI);
					}
				}
			} catch (Exception e) {
				logger.debug("Unable to analyse VRI dictionary : " + e.getMessage());
			}
		} else {
			logger.debug("No VRI dictionary found in DSS dictionary");
		}
	}

	private void readCerts(PdfDict dssDictionary) {
		extractCertsFromArray(dssDictionary, DSS_DICTIONARY_NAME, CERT_ARRAY_NAME_DSS);
	}

	private void readOcsps(PdfDict dssDictionary) {
		extractOCSPsFromArray(dssDictionary, DSS_DICTIONARY_NAME, OCSP_ARRAY_NAME_DSS);
	}

	private void readCrls(PdfDict dssDictionary) {
		extractCRLsFromArray(dssDictionary, DSS_DICTIONARY_NAME, CRL_ARRAY_NAME_DSS);
	}

	private void extractCRLsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		final PdfArray crlArray = dict.getAsArray(arrayName);
		if (crlArray != null) {
			logger.debug("There are {} CRLs in {} dictionary", crlArray.size(), dictionaryName);
			for (int ii = 0; ii < crlArray.size(); ii++) {
				try {
					final byte[] bytes = crlArray.getBytes(ii);
					final X509CRL x509CRL = DSSUtils.loadCRL(bytes);
					crlList.add(x509CRL);
				} catch (Exception e) {
					logger.debug("Unable to read CRL " + ii + " from " + dictionaryName + " dictionary : " + e.getMessage(), e);
				}
			}
		} else {
			logger.debug("No CRLs found in {} dictionary", dictionaryName);
		}
	}

	private void extractCertsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		final PdfArray certsArray = dict.getAsArray(arrayName);
		if (certsArray != null) {
			logger.debug("There are {} certificates in {} dictionary", certsArray.size(), dictionaryName);
			for (int ii = 0; ii < certsArray.size(); ii++) {
				try {
					final byte[] stream = certsArray.getBytes(ii);
					final CertificateToken cert = DSSUtils.loadCertificate(stream);
					certList.add(cert);
				} catch (Exception e) {
					logger.debug("Unable to read Cert " + ii + " from " + dictionaryName + " dictionary : " + e.getMessage(), e);
				}
			}
		} else {
			logger.debug("No Certs found in {} dictionary", dictionaryName);
		}
	}

	private void extractOCSPsFromArray(PdfDict dict, String dictionaryName, String arrayName) {
		PdfArray ocspArray = dict.getAsArray(arrayName);
		if (ocspArray != null) {
			logger.debug("There are {} OCSPs in {} dictionary", ocspArray.size(), dictionaryName);
			for (int ii = 0; ii < ocspArray.size(); ii++) {
				try {
					final byte[] stream = ocspArray.getBytes(ii);
					final OCSPResp ocspResp = new OCSPResp(stream);
					final BasicOCSPResp responseObject = (BasicOCSPResp) ocspResp.getResponseObject();
					ocspList.add(responseObject);
				} catch (Exception e) {
					logger.debug("Unable to read OCSP " + ii + " from " + dictionaryName + " dictionary : " + e.getMessage(), e);
				}
			}
		} else {
			logger.debug("No OCSPs found in {} dictionary", dictionaryName);
		}
	}

	public Set<X509CRL> getCrlList() {
		return Collections.unmodifiableSet(crlList);
	}

	public Set<BasicOCSPResp> getOcspList() {
		return Collections.unmodifiableSet(ocspList);
	}

	public Set<CertificateToken> getCertList() {
		return Collections.unmodifiableSet(certList);
	}
}