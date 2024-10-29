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

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictOCSPSource;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import org.bouncycastle.asn1.cms.AttributeTable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * OCSPSource that retrieves the OCSPResp from a PAdES Signature
 *
 */
@SuppressWarnings("serial")
public class PAdESOCSPSource extends OfflineOCSPSource {

	/** CMS OCSP source */
	private final PdfCmsOCSPSource cmsOCSPSource;

	/** DSS dictionary OCSP source */
	private final PdfDssDictOCSPSource dssDictOCSPSource;

	/**
	 * The default constructor
	 *
	 * @param pdfSignatureRevision {@link PdfSignatureRevision}
	 * @param vriDictionaryName {@link String} the corresponding VRI dictionary name to extract
	 * @param signedAttributes {@link AttributeTable}
	 */
	public PAdESOCSPSource(PdfSignatureRevision pdfSignatureRevision, final String vriDictionaryName,
						  AttributeTable signedAttributes) {
		Objects.requireNonNull(vriDictionaryName, "vriDictionaryName cannot be null!");
		this.cmsOCSPSource = new PdfCmsOCSPSource(signedAttributes);
		this.dssDictOCSPSource = new PdfDssDictOCSPSource(pdfSignatureRevision.getCompositeDssDictionary().getOcspSource(),
				pdfSignatureRevision.getDssDictionary(), vriDictionaryName);
	}

	@Override
	public List<RevocationToken<OCSP>> getRevocationTokens(CertificateToken certificateToken, CertificateToken issuerToken) {
		List<RevocationToken<OCSP>> revocationTokens = new ArrayList<>();
		revocationTokens.addAll(cmsOCSPSource.getRevocationTokens(certificateToken, issuerToken));
		revocationTokens.addAll(dssDictOCSPSource.getRevocationTokens(certificateToken, issuerToken));
		return revocationTokens;
	}

	/**
	 * Returns a map of all OCSP entries contained in DSS dictionary or into nested
	 * VRI dictionaries
	 *
	 * @return a map of OCSP binaries with their object ids
	 */
	public Map<PdfObjectKey, OCSPResponseBinary> getOcspMap() {
		return dssDictOCSPSource.getOcspMap();
	}

	@Override
	public List<EncapsulatedRevocationTokenIdentifier<OCSP>> getDSSDictionaryBinaries() {
		return dssDictOCSPSource.getDSSDictionaryBinaries();
	}

	@Override
	public List<RevocationToken<OCSP>> getDSSDictionaryTokens() {
		return dssDictOCSPSource.getDSSDictionaryTokens();
	}

	@Override
	public List<EncapsulatedRevocationTokenIdentifier<OCSP>> getVRIDictionaryBinaries() {
		return dssDictOCSPSource.getVRIDictionaryBinaries();
	}

	@Override
	public List<RevocationToken<OCSP>> getVRIDictionaryTokens() {
		return dssDictOCSPSource.getVRIDictionaryTokens();
	}

	@Override
	public List<EncapsulatedRevocationTokenIdentifier<OCSP>> getADBERevocationValuesBinaries() {
		return cmsOCSPSource.getADBERevocationValuesBinaries();
	}

	@Override
	public List<RevocationToken<OCSP>> getADBERevocationValuesTokens() {
		return dssDictOCSPSource.getADBERevocationValuesTokens();
	}

	@Override
	public Map<EncapsulatedRevocationTokenIdentifier<OCSP>, Set<RevocationOrigin>> getAllRevocationBinariesWithOrigins() {
		Map<EncapsulatedRevocationTokenIdentifier<OCSP>, Set<RevocationOrigin>> result = new HashMap<>();
		populateMapWithSet(result, cmsOCSPSource.getAllRevocationBinariesWithOrigins());
		populateMapWithSet(result, dssDictOCSPSource.getAllRevocationBinariesWithOrigins());
		return result;
	}

	@Override
	public Map<RevocationToken<OCSP>, Set<RevocationOrigin>> getAllRevocationTokensWithOrigins() {
		Map<RevocationToken<OCSP>, Set<RevocationOrigin>> result = new HashMap<>();
		populateMapWithSet(result, cmsOCSPSource.getAllRevocationTokensWithOrigins());
		populateMapWithSet(result, dssDictOCSPSource.getAllRevocationTokensWithOrigins());
		return result;
	}

	private <R extends Object> void populateMapWithSet(Map<R, Set<RevocationOrigin>> mapToPopulate,
													   Map<R, Set<RevocationOrigin>> mapToAdd) {
		for (Map.Entry<R, Set<RevocationOrigin>> entry : mapToAdd.entrySet()) {
			Set<RevocationOrigin> revocationOrigins = mapToPopulate.get(entry.getKey());
			if (revocationOrigins == null) {
				revocationOrigins = new HashSet<>();
			}
			revocationOrigins.addAll(entry.getValue());
			mapToPopulate.put(entry.getKey(), revocationOrigins);
		}
	}

}
