package eu.europa.esig.dss.tsl.function.converter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import eu.europa.esig.dss.spi.tsl.TrustService;
import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.builder.TrustServiceProviderBuilder;
import eu.europa.esig.dss.tsl.function.OfficialRegistrationIdentifierPredicate;
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

public class TrustServiceProviderConverter implements Function<TSPType, TrustServiceProvider> {
	
	private String territory;
	
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
		InternationalNamesTypeConverter converter = new InternationalNamesTypeConverter();
		tspBuilder.setTerritory(territory);
		tspBuilder.setNames(converter.apply(tspInformation.getTSPName()));
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

		List<String> result = new ArrayList<String>();
		if (internationalNamesType != null && Utils.isCollectionNotEmpty(internationalNamesType.getName())) {
			for (MultiLangNormStringType multiLangNormString : internationalNamesType.getName()) {
				final String value = multiLangNormString.getValue();
				if (predicate.test(value)) {
					result.add(value);
				}
			}
		}

		return result;
	}

	private Map<String, String> extractPostalAddress(PostalAddressListType postalAddressList) {
		Map<String, String> result = new HashMap<String, String>();
		if (postalAddressList != null && Utils.isCollectionNotEmpty(postalAddressList.getPostalAddress())) {
			for (PostalAddressType postalAddress : postalAddressList.getPostalAddress()) {
				String lang = postalAddress.getLang();
				// Collect 1st / lang
				if (result.get(lang) == null) {
					result.put(lang, getPostalAddress(postalAddress));
				}
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
		Map<String, List<String>> result = new HashMap<String, List<String>>();
		if (electronicAddress != null && Utils.isCollectionNotEmpty(electronicAddress.getURI())) {
			for (NonEmptyMultiLangURIType uriAndLang : electronicAddress.getURI()) {
				addEntry(result, uriAndLang.getLang(), uriAndLang.getValue());
			}
		}
		return result;
	}

	private Map<String, String> extractInformationURI(NonEmptyMultiLangURIListType tspInformationURI) {
		Map<String, String> result = new HashMap<String, String>();
		if (tspInformationURI != null && Utils.isCollectionNotEmpty(tspInformationURI.getURI())) {
			for (NonEmptyMultiLangURIType uriAndLang : tspInformationURI.getURI()) {
				String lang = uriAndLang.getLang();
				// Collect 1st / lang
				if (result.get(lang) == null) {
					result.put(lang, uriAndLang.getValue());
				}
			}
		}
		return result;
	}

	private void addEntry(Map<String, List<String>> result, final String lang, final String value) {
		List<String> resultsByLang = result.get(lang);
		if (resultsByLang == null) {
			resultsByLang = new ArrayList<String>();
			result.put(lang, resultsByLang);
		}
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
