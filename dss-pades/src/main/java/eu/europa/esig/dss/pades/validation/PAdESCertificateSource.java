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
package eu.europa.esig.dss.pades.validation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.cades.validation.CAdESCertificateSource;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.utils.Utils;

/**
 * CertificateSource that will retrieve the certificate from a PAdES Signature
 *
 */
@SuppressWarnings("serial")
public class PAdESCertificateSource extends CAdESCertificateSource {

	private final PdfDssDictCertificateSource dssDictionaryCertificateSource;

	/**
	 * The default constructor for PAdESCertificateSource.
	 *
	 * @param pdfSignatureRevision the used {@link PdfSignatureRevision}
	 * @param signerInformation    the current {@link SignerInformation}
	 */
	public PAdESCertificateSource(final PdfSignatureRevision pdfSignatureRevision, final SignerInformation signerInformation) {
		super(pdfSignatureRevision.getCMSSignedData(), signerInformation);

		this.dssDictionaryCertificateSource = new PdfDssDictCertificateSource(pdfSignatureRevision.getDssDictionary());
		extractFromDssDictSource();
	}

	private void extractFromDssDictSource() {
		for (CertificateToken certToken : dssDictionaryCertificateSource.getDSSDictionaryCertValues()) {
			addCertificate(certToken, CertificateOrigin.DSS_DICTIONARY);
		}
		for (CertificateToken certToken : dssDictionaryCertificateSource.getVRIDictionaryCertValues()) {
			addCertificate(certToken, CertificateOrigin.VRI_DICTIONARY);
		}
	}

	public Map<Long, CertificateToken> getCertificateMap() {
		return dssDictionaryCertificateSource.getCertificateMap();
	}

	@Override
	public List<CertificateToken> getCertificateValues() {
		// Not applicable for PAdES
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getCompleteCertificateRefs() {
		// Not applicable for PAdES
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getAttributeCertificateRefs() {
		// Not applicable for PAdES
		return Collections.emptyList();
	}

	@Override
	public List<CertificateToken> getDSSDictionaryCertValues() {
		return dssDictionaryCertificateSource.getDSSDictionaryCertValues();
	}

	@Override
	public List<CertificateToken> getVRIDictionaryCertValues() {
		return dssDictionaryCertificateSource.getVRIDictionaryCertValues();
	}

}
