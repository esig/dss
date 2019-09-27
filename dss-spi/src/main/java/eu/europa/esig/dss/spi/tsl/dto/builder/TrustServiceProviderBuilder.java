package eu.europa.esig.dss.spi.tsl.dto.builder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.spi.tsl.dto.TrustService;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceProvider;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.dto.TrustService.TrustServiceBuilder;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.utils.Utils;

public class TrustServiceProviderBuilder {
	
	private Map<String, List<String>> names;
	private Map<String, List<String>> tradeNames;
	private List<String> registrationIdentifiers;
	private Map<String, String> postalAddresses;
	private Map<String, List<String>> electronicAddresses;
	private Map<String, String> information;
	private List<TrustService> services;
	
	/**
	 * Default constructor
	 */
	public TrustServiceProviderBuilder() {
	}
	
	public TrustServiceProvider build() {
		return new TrustServiceProvider(this);
	}

	public Map<String, List<String>> getNames() {
		return getUnmodifiableMapWithLists(names);
	}

	public TrustServiceProviderBuilder setNames(Map<String, List<String>> names) {
		this.names = names;
		return this;
	}

	public Map<String, List<String>> getTradeNames() {
		return getUnmodifiableMapWithLists(tradeNames);
	}

	public TrustServiceProviderBuilder setTradeNames(Map<String, List<String>> tradeNames) {
		this.tradeNames = tradeNames;
		return this;
	}

	public List<String> getRegistrationIdentifiers() {
		return getUnmodifiableList(registrationIdentifiers);
	}

	public TrustServiceProviderBuilder setRegistrationIdentifiers(List<String> registrationIdentifiers) {
		this.registrationIdentifiers = registrationIdentifiers;
		return this;
	}

	public Map<String, String> getPostalAddresses() {
		return getUnmodifiableMap(postalAddresses);
	}

	public TrustServiceProviderBuilder setPostalAddresses(Map<String, String> postalAddresses) {
		this.postalAddresses = postalAddresses;
		return this;
	}

	public Map<String, List<String>> getElectronicAddresses() {
		return getUnmodifiableMapWithLists(electronicAddresses);
	}

	public TrustServiceProviderBuilder setElectronicAddresses(Map<String, List<String>> electronicAddresses) {
		this.electronicAddresses = electronicAddresses;
		return this;
	}

	public Map<String, String> getInformation() {
		return getUnmodifiableMap(information);
	}

	public TrustServiceProviderBuilder setInformation(Map<String, String> information) {
		this.information = information;
		return this;
	}
	public List<TrustService> getServices() {
		return getUnmodifiableTrustServices(services);
	}

	public TrustServiceProviderBuilder setServices(List<TrustService> services) {
		this.services = services;
		return this;
	}
	
	private <T extends Object> List<T> getUnmodifiableList(List<T> originalList) {
		List<T> newList = new ArrayList<T>();
		if (Utils.isCollectionNotEmpty(originalList)) {
			newList.addAll(originalList);
		}
		return Collections.unmodifiableList(newList);
	}
	
	private <T extends Object, K extends Object> Map<T, K> getUnmodifiableMap(Map<T, K> originalMap) {
		Map<T, K> newMap = new HashMap<T, K>();
		if (Utils.isMapNotEmpty(originalMap)) {
			newMap.putAll(originalMap);
		}
		return Collections.unmodifiableMap(newMap);
	}
	
	private Map<String, List<String>> getUnmodifiableMapWithLists(Map<String, List<String>> originalMap) {
		Map<String, List<String>> copyMap = new HashMap<String, List<String>>();
		if (Utils.isMapNotEmpty(originalMap)) {
			for (Map.Entry<String, List<String>> mapEntry : originalMap.entrySet()) {
				copyMap.put(mapEntry.getKey(), Collections.unmodifiableList(mapEntry.getValue()));
			}
		}
		return Collections.unmodifiableMap(copyMap);
	}
	
	private List<TrustService> getUnmodifiableTrustServices(List<TrustService> originalTrustServices) {
		List<TrustService> copyTrustServices = new ArrayList<TrustService>();
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
		
		List<TrustServiceStatusAndInformationExtensions> copyTSSAndIEs = new ArrayList<TrustServiceStatusAndInformationExtensions>();
		
		Iterator<TrustServiceStatusAndInformationExtensions> iterator = timeDependentValues.iterator();
		while (iterator.hasNext()) {
			TrustServiceStatusAndInformationExtensions status = iterator.next();
			
			TrustServiceStatusAndInformationExtensionsBuilder builder = 
					new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder();
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
		
		return new TimeDependentValues<TrustServiceStatusAndInformationExtensions>(copyTSSAndIEs);
	}

}
