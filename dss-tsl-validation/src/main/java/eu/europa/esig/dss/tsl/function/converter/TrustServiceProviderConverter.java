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
package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.model.tsl.TrustService;
import eu.europa.esig.dss.model.tsl.TrustServiceProvider;
import eu.europa.esig.dss.tsl.sync.TrustServiceProviderBuilder;
import eu.europa.esig.dss.tsl.function.OfficialRegistrationIdentifierPredicate;
import eu.europa.esig.dss.tsl.function.TradeNamePredicate;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.AddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.ElectronicAddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.PostalAddressListType;
import eu.europa.esig.trustedlist.jaxb.tsl.PostalAddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServicesListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The class is used to convert {@code TSPType} to {@code TrustServiceProvider}
 *
 */
public class TrustServiceProviderConverter implements Function<TSPType, TrustServiceProvider> {

	/** The country code */
	private String territory;

	/**
	 * Default constructor with null territory country code
	 */
	public TrustServiceProviderConverter() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param territory {@link String}
	 * @return {@link TrustServiceProviderConverter}
	 */
	public TrustServiceProviderConverter setTerritory(String territory) {
		this.territory = territory;
		return this;
	}

	@Override
	public TrustServiceProvider apply(TSPType original) {
		TrustServiceProviderBuilder tspBuilder = new TrustServiceProviderBuilder();
		
		extractTSPInfo(tspBuilder, original.getTSPInformation());
		tspBuilder.setServices(extractTrustServices(original.getTSPServices()));

		return tspBuilder.build();
	}

	private void extractTSPInfo(TrustServiceProviderBuilder tspBuilder, TSPInformationType tspInformation) {
		tspBuilder.setTerritory(territory);

		InternationalNamesTypeConverter converter = new InternationalNamesTypeConverter();
		tspBuilder.setNames(converter.apply(tspInformation.getTSPName()));

		converter = new InternationalNamesTypeConverter(new TradeNamePredicate()); // filter registration identifiers
		tspBuilder.setTradeNames(converter.apply(tspInformation.getTSPTradeName()));

		tspBuilder.setRegistrationIdentifiers(extractRegistrationIdentifiers(tspInformation.getTSPTradeName()));

		AddressType tspAddress = tspInformation.getTSPAddress();
		if (tspAddress != null) {
			tspBuilder.setPostalAddresses(extractPostalAddress(tspAddress.getPostalAddresses()));
			tspBuilder.setElectronicAddresses(extractElectronicAddress(tspAddress.getElectronicAddress()));
		}

		tspBuilder.setInformation(extractInformationURI(tspInformation.getTSPInformationURI()));
	}

	private List<String> extractRegistrationIdentifiers(InternationalNamesType internationalNamesType) {
		OfficialRegistrationIdentifierPredicate predicate = new OfficialRegistrationIdentifierPredicate();

		List<String> result = new ArrayList<>();
		if (internationalNamesType != null && Utils.isCollectionNotEmpty(internationalNamesType.getName())) {
			for (MultiLangNormStringType multiLangNormString : internationalNamesType.getName()) {
				final String value = multiLangNormString.getValue();
				if (predicate.test(value) && !result.contains(value)) {
					result.add(value);
				}
			}
		}

		return result;
	}

	private Map<String, String> extractPostalAddress(PostalAddressListType postalAddressList) {
		Map<String, String> result = new HashMap<>();
		if (postalAddressList != null && Utils.isCollectionNotEmpty(postalAddressList.getPostalAddress())) {
			for (PostalAddressType postalAddress : postalAddressList.getPostalAddress()) {
				String lang = postalAddress.getLang();
				// Collect 1st / lang
				result.computeIfAbsent(lang, k -> getPostalAddress(postalAddress));
			}
		}
		return result;
	}

	private String getPostalAddress(PostalAddressType postalAddress) {
		StringBuilder sb = new StringBuilder();
		if (Utils.isStringNotEmpty(postalAddress.getStreetAddress())) {
			sb.append(postalAddress.getStreetAddress());
			sb.append(", ");
		}
		if (Utils.isStringNotEmpty(postalAddress.getPostalCode())) {
			sb.append(postalAddress.getPostalCode());
			sb.append(", ");
		}
		if (Utils.isStringNotEmpty(postalAddress.getLocality())) {
			sb.append(postalAddress.getLocality());
			sb.append(", ");
		}
		if (Utils.isStringNotEmpty(postalAddress.getStateOrProvince())) {
			sb.append(postalAddress.getStateOrProvince());
			sb.append(", ");
		}
		if (Utils.isStringNotEmpty(postalAddress.getCountryName())) {
			sb.append(postalAddress.getCountryName());
		}
		return sb.toString();
	}

	private Map<String, List<String>> extractElectronicAddress(ElectronicAddressType electronicAddress) {
		Map<String, List<String>> result = new HashMap<>();
		if (electronicAddress != null && Utils.isCollectionNotEmpty(electronicAddress.getURI())) {
			for (NonEmptyMultiLangURIType uriAndLang : electronicAddress.getURI()) {
				addEntry(result, uriAndLang.getLang(), uriAndLang.getValue());
			}
		}
		return result;
	}

	private Map<String, String> extractInformationURI(NonEmptyMultiLangURIListType tspInformationURI) {
		Map<String, String> result = new HashMap<>();
		if (tspInformationURI != null && Utils.isCollectionNotEmpty(tspInformationURI.getURI())) {
			for (NonEmptyMultiLangURIType uriAndLang : tspInformationURI.getURI()) {
				String lang = uriAndLang.getLang();
				// Collect 1st / lang
				result.computeIfAbsent(lang, k -> uriAndLang.getValue());
			}
		}
		return result;
	}

	private void addEntry(Map<String, List<String>> result, final String lang, final String value) {
		List<String> resultsByLang = result.computeIfAbsent(lang, k -> new ArrayList<>());
		resultsByLang.add(value);
	}

	private List<TrustService> extractTrustServices(TSPServicesListType tspServicesList) {
		if (tspServicesList != null && Utils.isCollectionNotEmpty(tspServicesList.getTSPService())) {
			return tspServicesList.getTSPService().stream().map(new TrustServiceConverter()).collect(Collectors.toList());
		} else {
			return Collections.emptyList();
		}
	}

}
