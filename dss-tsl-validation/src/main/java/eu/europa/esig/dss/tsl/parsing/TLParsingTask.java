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
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.tsl.function.NonEmptyTrustService;
import eu.europa.esig.dss.tsl.function.converter.TrustServiceProviderConverter;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServicesListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Parses a TL and returns {@code TLParsingResult}
 */
public class TLParsingTask extends AbstractParsingTask<TLParsingResult> {

	/** The TLSource to parse */
	private final TLSource tlSource;

	/**
	 * The default constructor
	 *
	 * @param document {@link DSSDocument} TL document to parse
	 * @param tlSource {@link TLSource}
	 */
	public TLParsingTask(DSSDocument document, TLSource tlSource) {
		super(document);
		Objects.requireNonNull(tlSource, "The TLSource is null");
		this.tlSource = tlSource;
	}

	@Override
	public TLParsingResult get() {
		TLParsingResult result = new TLParsingResult();
		TrustStatusListType jaxbObject = getJAXBObject();

		parseSchemeInformation(result, jaxbObject.getSchemeInformation());
		parseTrustServiceProviderList(result, jaxbObject.getTrustServiceProviderList());
		verifyTLVersionConformity(result, result.getVersion());

		return result;
	}

	private void parseSchemeInformation(TLParsingResult result, TSLSchemeInformationType schemeInformation) {
		commonParseSchemeInformation(result, schemeInformation);
	}

	private void parseTrustServiceProviderList(TLParsingResult result, TrustServiceProviderListType trustServiceProviderList) {
		if (trustServiceProviderList != null && Utils.isCollectionNotEmpty(trustServiceProviderList.getTrustServiceProvider())) {
			List<TSPType> filteredTrustServiceProviders = filter(trustServiceProviderList.getTrustServiceProvider());
			result.setTrustServiceProviders(Collections.unmodifiableList(
					filteredTrustServiceProviders.stream().map(new TrustServiceProviderConverter().setTerritory(result.getTerritory())).collect(Collectors.toList())));
		} else {
			result.setTrustServiceProviders(Collections.emptyList());
		}
	}

	private List<TSPType> filter(List<TSPType> trustServiceProviders) {

		List<TSPType> filteredTSP = trustServiceProviders;

		// 1. Filter the TSP with the predicate
		if (tlSource.getTrustServiceProviderPredicate() != null) {
			filteredTSP = filteredTSP.stream().filter(tlSource.getTrustServiceProviderPredicate()).collect(Collectors.toList());
		}

		// 2. Foreach TSP, filter the trust services with the predicate
		if (tlSource.getTrustServicePredicate() != null) {
			for (TSPType tspType : filteredTSP) {
				TSPServicesListType tspServices = tspType.getTSPServices();
				if (tspServices != null && Utils.isCollectionNotEmpty(tspServices.getTSPService())) {
					List<TSPServiceType> filteredTrustServices = tspServices.getTSPService().stream().filter(tlSource.getTrustServicePredicate())
							.collect(Collectors.toList());
					TSPServicesListType newTspServices = new TSPServicesListType();
					if (!filteredTrustServices.isEmpty()) {
						newTspServices.getTSPService().addAll(filteredTrustServices);
					}
					tspType.setTSPServices(newTspServices);
				}
			}
		}

		// 3. Remove TSP with empty trust services
		return filteredTSP.stream().filter(new NonEmptyTrustService()).collect(Collectors.toList());
	}
}
