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

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictCRLSource;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import org.bouncycastle.asn1.cms.AttributeTable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * CRLSource that will retrieve the CRL from a PAdES Signature
 */
@SuppressWarnings("serial")
public class PAdESCRLSource extends OfflineCRLSource {

	/** CMS CRL source */
	private final PdfCmsCRLSource cmsCrlSource;

	/** DSS dictionary CRL source */
	private final PdfDssDictCRLSource dssDictCrlSource;

	/**
	 * The default constructor
	 *
	 * @param pdfSignatureRevision {@link PdfSignatureRevision}
	 * @param vriDictionaryName {@link String} the corresponding VRI dictionary name to extract
	 * @param signedAttributes {@link AttributeTable}
	 */
	public PAdESCRLSource(PdfSignatureRevision pdfSignatureRevision, final String vriDictionaryName,
						  AttributeTable signedAttributes) {
		Objects.requireNonNull(vriDictionaryName, "vriDictionaryName cannot be null!");
		this.cmsCrlSource = new PdfCmsCRLSource(signedAttributes);
		this.dssDictCrlSource = new PdfDssDictCRLSource(pdfSignatureRevision.getCompositeDssDictionary().getCrlSource(),
				pdfSignatureRevision.getDssDictionary(), vriDictionaryName);
	}
	@Override
	public List<RevocationToken<CRL>> getRevocationTokens(CertificateToken certificateToken, CertificateToken issuerToken) {
		List<RevocationToken<CRL>> revocationTokens = new ArrayList<>();
		revocationTokens.addAll(cmsCrlSource.getRevocationTokens(certificateToken, issuerToken));
		revocationTokens.addAll(dssDictCrlSource.getRevocationTokens(certificateToken, issuerToken));
		return revocationTokens;
	}

	/**
	 * Returns a map of all CRL entries contained in DSS dictionary or into nested
	 * VRI dictionaries
	 *
	 * @return a map of CRL binaries with their object ids
	 */
	public Map<Long, CRLBinary> getCrlMap() {
		return dssDictCrlSource.getCrlMap();
	}

	@Override
	public List<EncapsulatedRevocationTokenIdentifier<CRL>> getDSSDictionaryBinaries() {
		return dssDictCrlSource.getDSSDictionaryBinaries();
	}

	@Override
	public List<RevocationToken<CRL>> getDSSDictionaryTokens() {
		return dssDictCrlSource.getDSSDictionaryTokens();
	}

	@Override
	public List<EncapsulatedRevocationTokenIdentifier<CRL>> getVRIDictionaryBinaries() {
		return dssDictCrlSource.getVRIDictionaryBinaries();
	}

	@Override
	public List<RevocationToken<CRL>> getVRIDictionaryTokens() {
		return dssDictCrlSource.getVRIDictionaryTokens();
	}

	@Override
	public List<EncapsulatedRevocationTokenIdentifier<CRL>> getADBERevocationValuesBinaries() {
		return cmsCrlSource.getADBERevocationValuesBinaries();
	}

	@Override
	public List<RevocationToken<CRL>> getADBERevocationValuesTokens() {
		return dssDictCrlSource.getADBERevocationValuesTokens();
	}

	@Override
	public Map<EncapsulatedRevocationTokenIdentifier<CRL>, Set<RevocationOrigin>> getAllRevocationBinariesWithOrigins() {
		Map<EncapsulatedRevocationTokenIdentifier<CRL>, Set<RevocationOrigin>> result = new HashMap<>();
		populateMapWithSet(result, cmsCrlSource.getAllRevocationBinariesWithOrigins());
		populateMapWithSet(result, dssDictCrlSource.getAllRevocationBinariesWithOrigins());
		return result;
	}

	@Override
	public Map<RevocationToken<CRL>, Set<RevocationOrigin>> getAllRevocationTokensWithOrigins() {
		Map<RevocationToken<CRL>, Set<RevocationOrigin>> result = new HashMap<>();
		populateMapWithSet(result, cmsCrlSource.getAllRevocationTokensWithOrigins());
		populateMapWithSet(result, dssDictCrlSource.getAllRevocationTokensWithOrigins());
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
