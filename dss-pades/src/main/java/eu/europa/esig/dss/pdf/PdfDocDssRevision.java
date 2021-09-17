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

import eu.europa.esig.dss.pades.validation.PdfDssDictCRLSource;
import eu.europa.esig.dss.pades.validation.PdfDssDictCertificateSource;
import eu.europa.esig.dss.pades.validation.PdfDssDictOCSPSource;
import eu.europa.esig.dss.pades.validation.PdfModificationDetection;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;

import java.util.List;
import java.util.Objects;

/**
 * This class represents an LT-level PDF revision containing a DSS dictionary
 *
 */
public class PdfDocDssRevision implements PdfRevision {
	
	private static final long serialVersionUID = -1369264311522424583L;

	/** The DSS dictionary from the revision */
	private final PdfDssDict dssDictionary;

	/** Cached certificate source */
	private PdfDssDictCertificateSource certificateSource;

	/** Cached CRL source */
	private PdfDssDictCRLSource crlSource;

	/** Cached OCSP source */
	private PdfDssDictOCSPSource ocspSource;

	/**
	 * Default constructor
	 *
	 * @param dssDictionary {@link PdfDssDict}
	 */
	public PdfDocDssRevision(final PdfDssDict dssDictionary) {
		Objects.requireNonNull(dssDictionary, "The dssDictionary cannot be null!");
		this.dssDictionary = dssDictionary;
	}

	/**
	 * Returns DSS dictionary
	 * 
	 * @return {@link PdfDssDict}
	 */
	public PdfDssDict getDssDictionary() {
		return dssDictionary;
	}

	@Override
	public PdfSignatureDictionary getPdfSigDictInfo() {
		// not applicable for DSS revision
		return null;
	}

	@Override
	public List<String> getFieldNames() {
		// not applicable for DSS revision
		return null;
	}

	@Override
	public PdfModificationDetection getModificationDetection() {
		// not applicable
		return null;
	}

	/**
	 * Returns a corresponding {@code CertificateSource}
	 *
	 * @return {@link PdfDssDictCertificateSource}
	 */
	public PdfDssDictCertificateSource getCertificateSource() {
		if (certificateSource == null) {
			certificateSource = new PdfDssDictCertificateSource(dssDictionary);
		}
		return certificateSource;
	}

	/**
	 * Returns a corresponding {@code CRLSource}
	 *
	 * @return {@link PdfDssDictCRLSource}
	 */
	public PdfDssDictCRLSource getCRLSource() {
		if (crlSource == null) {
			crlSource = new PdfDssDictCRLSource(dssDictionary);
		}
		return crlSource;
	}

	/**
	 * Returns a corresponding {@code OCSPSource}
	 *
	 * @return {@link PdfDssDictOCSPSource}
	 */
	public PdfDssDictOCSPSource getOCSPSource() {
		if (ocspSource == null) {
			ocspSource = new PdfDssDictOCSPSource(dssDictionary);
		}
		return ocspSource;
	}

}
