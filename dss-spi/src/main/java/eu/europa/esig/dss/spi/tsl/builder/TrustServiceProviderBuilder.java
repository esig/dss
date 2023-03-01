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
package eu.europa.esig.dss.spi.tsl.builder;

import eu.europa.esig.dss.spi.tsl.TrustService;
import eu.europa.esig.dss.spi.tsl.TrustService.TrustServiceBuilder;
import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds {@code TrustServiceProvider}
 */
public class TrustServiceProviderBuilder {

	/** Map of names (the key is the language) */
	private Map<String, List<String>> names;

	/** Map of trade names */
	private Map<String, List<String>> tradeNames;

	/** List of registration identifiers */
	private List<String> registrationIdentifiers;

	/** Map of postal addresses */
	private Map<String, String> postalAddresses;

	/** Map of electronic addresses */
	private Map<String, List<String>> electronicAddresses;

	/** Map of information */
	private Map<String, String> information;

	/** List of trust services */
	private List<TrustService> services;

	/** The territory (country) */
	private String territory;

	/**
	 * Default constructor
	 */
	public TrustServiceProviderBuilder() {
	}

	/**
	 * Copy the original object
	 * 
	 * @param original the original trust service provider
	 */
	public TrustServiceProviderBuilder(TrustServiceProvider original) {
		this.names = original.getNames();
		this.tradeNames = original.getTradeNames();
		this.registrationIdentifiers = original.getRegistrationIdentifiers();
		this.postalAddresses = original.getPostalAddresses();
		this.electronicAddresses = original.getElectronicAddresses();
		this.information = original.getInformation();
		this.services = original.getServices();
		this.territory = original.getTerritory();
	}

	/**
	 * Builds {@code TrustServiceProvider}
	 *
	 * @return {@link TrustServiceProvider}
	 */
	public TrustServiceProvider build() {
		return new TrustServiceProvider(this);
	}

	/**
	 * Gets a map of names (first key is the language)
	 *
	 * @return a map of names
	 */
	public Map<String, List<String>> getNames() {
		return getUnmodifiableMapWithLists(names);
	}

	/**
	 * Sets a map of names
	 *
	 * @param names a map of names (first key is the language)
	 * @return this {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProviderBuilder setNames(Map<String, List<String>> names) {
		this.names = names;
		return this;
	}

	/**
	 * Gets a map of trade names
	 *
	 * @return a map of trade names
	 */
	public Map<String, List<String>> getTradeNames() {
		return getUnmodifiableMapWithLists(tradeNames);
	}

	/**
	 * Sets a map of trade names
	 *
	 * @param tradeNames a map of trade names (first key is the language)
	 * @return this {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProviderBuilder setTradeNames(Map<String, List<String>> tradeNames) {
		this.tradeNames = tradeNames;
		return this;
	}

	/**
	 * Gets registration identifiers
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getRegistrationIdentifiers() {
		return getUnmodifiableList(registrationIdentifiers);
	}

	/**
	 * Sets registration identifiers
	 *
	 * @param registrationIdentifiers a list of {@link String}s
	 * @return this {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProviderBuilder setRegistrationIdentifiers(List<String> registrationIdentifiers) {
		this.registrationIdentifiers = registrationIdentifiers;
		return this;
	}

	/**
	 * Gets a map of postal addresses
	 *
	 * @return a map of postal addresses
	 */
	public Map<String, String> getPostalAddresses() {
		return getUnmodifiableMap(postalAddresses);
	}

	/**
	 * Sets a map of postal addresses
	 *
	 * @param postalAddresses a map of postal addresses
	 * @return this {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProviderBuilder setPostalAddresses(Map<String, String> postalAddresses) {
		this.postalAddresses = postalAddresses;
		return this;
	}

	/**
	 * Gets a map of electronic addresses
	 *
	 * @return a map of electronic addresses
	 */
	public Map<String, List<String>> getElectronicAddresses() {
		return getUnmodifiableMapWithLists(electronicAddresses);
	}

	/**
	 * Sets a map of electronic addresses
	 *
	 * @param electronicAddresses a map of electronic addresses
	 * @return this {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProviderBuilder setElectronicAddresses(Map<String, List<String>> electronicAddresses) {
		this.electronicAddresses = electronicAddresses;
		return this;
	}

	/**
	 * Gets a map of information
	 *
	 * @return a map of information
	 */
	public Map<String, String> getInformation() {
		return getUnmodifiableMap(information);
	}

	/**
	 * Sets a map of information
	 *
	 * @param information a map of information
	 * @return this {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProviderBuilder setInformation(Map<String, String> information) {
		this.information = information;
		return this;
	}

	/**
	 * Gets a list of trust services
	 *
	 * @return a list of {@link TrustService}s
	 */
	public List<TrustService> getServices() {
		return getUnmodifiableTrustServices(services);
	}

	/**
	 * Sets a list of trust services
	 *
	 * @param services a list of {@link TrustService}s
	 * @return this {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProviderBuilder setServices(List<TrustService> services) {
		this.services = services;
		return this;
	}

	/**
	 * Gets territory (country)
	 *
	 * @return {@link String}
	 */
	public String getTerritory() {
		return territory;
	}

	/**
	 * Sets territory (country)
	 *
	 * @param territory {@link String}
	 * @return this {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProviderBuilder setTerritory(String territory) {
		this.territory = territory;
		return this;
	}
	
	private <T extends Object> List<T> getUnmodifiableList(List<T> originalList) {
		List<T> newList = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(originalList)) {
			newList.addAll(originalList);
		}
		return Collections.unmodifiableList(newList);
	}
	
	private <T extends Object, K extends Object> Map<T, K> getUnmodifiableMap(Map<T, K> originalMap) {
		Map<T, K> newMap = new HashMap<>();
		if (Utils.isMapNotEmpty(originalMap)) {
			newMap.putAll(originalMap);
		}
		return Collections.unmodifiableMap(newMap);
	}
	
	private Map<String, List<String>> getUnmodifiableMapWithLists(Map<String, List<String>> originalMap) {
		Map<String, List<String>> copyMap = new HashMap<>();
		if (Utils.isMapNotEmpty(originalMap)) {
			for (Map.Entry<String, List<String>> mapEntry : originalMap.entrySet()) {
				copyMap.put(mapEntry.getKey(), Collections.unmodifiableList(mapEntry.getValue()));
			}
		}
		return Collections.unmodifiableMap(copyMap);
	}
	
	private List<TrustService> getUnmodifiableTrustServices(List<TrustService> originalTrustServices) {
		List<TrustService> copyTrustServices = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(originalTrustServices)) {
			for (TrustService trustService : originalTrustServices) {
				TrustServiceBuilder trustServiceBuilder = new TrustService.TrustServiceBuilder();
				TrustService copyTrustService = trustServiceBuilder.setCertificates(getUnmodifiableList(trustService.getCertificates()))
						.setStatusAndInformationExtensions(getUnmodifiableTimeDependentValues(trustService.getStatusAndInformationExtensions()))
						.build();
				copyTrustServices.add(copyTrustService);
			}
		}
		return Collections.unmodifiableList(copyTrustServices);
	}
	
	private TimeDependentValues<TrustServiceStatusAndInformationExtensions> getUnmodifiableTimeDependentValues(
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> timeDependentValues) {
		List<TrustServiceStatusAndInformationExtensions> copyTSSAndIEs = new ArrayList<>();

		for (TrustServiceStatusAndInformationExtensions status : timeDependentValues) {
			TrustServiceStatusAndInformationExtensionsBuilder builder =
					new TrustServiceStatusAndInformationExtensionsBuilder();
			TrustServiceStatusAndInformationExtensions copyStatus = builder.setNames(getUnmodifiableMapWithLists(status.getNames()))
					.setType(status.getType())
					.setStatus(status.getStatus())
					.setConditionsForQualifiers(getUnmodifiableList(status.getConditionsForQualifiers()))
					.setAdditionalServiceInfoUris(getUnmodifiableList(status.getAdditionalServiceInfoUris()))
					.setServiceSupplyPoints(getUnmodifiableList(status.getServiceSupplyPoints()))
					.setExpiredCertsRevocationInfo(status.getExpiredCertsRevocationInfo())
					.setStartDate(status.getStartDate())
					.setEndDate(status.getEndDate())
					.build();
			copyTSSAndIEs.add(copyStatus);
		}
		
		return new TimeDependentValues<>(copyTSSAndIEs);
	}

}
