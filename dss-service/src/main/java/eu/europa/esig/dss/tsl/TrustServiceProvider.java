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
package eu.europa.esig.dss.tsl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import eu.europa.esig.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.jaxb.tsl.PostalAddressType;
import eu.europa.esig.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.jaxb.tsl.ServiceHistoryType;
import eu.europa.esig.jaxb.tsl.TSPServiceType;
import eu.europa.esig.jaxb.tsl.TSPType;

/**
 * Wrapper for the tag TrustServiceProvider
 *
 *
 */

class TrustServiceProvider {

	private TSPType tspType;

	/**
	 * The default constructor for TrustServiceProvider.
	 *
	 * @param tspType
	 */
	public TrustServiceProvider(TSPType tspType) {

		this.tspType = tspType;
	}

	/**
	 * Retrieves the list of current and historical services from the encapsulated provider
	 *
	 * @return The list of current and history services, in descending order.
	 */
	public List<AbstractTrustService> getTrustServiceList() {

		final List<AbstractTrustService> providerList = new ArrayList<AbstractTrustService>();
		for (final TSPServiceType service : tspType.getTSPServices().getTSPService()) {

			final List<AbstractTrustService> trustServiceList = new ArrayList<AbstractTrustService>();

			final CurrentTrustService currentService = new CurrentTrustService(service);
			trustServiceList.add(currentService);

			final ServiceHistoryType serviceHistory = service.getServiceHistory();
			if (serviceHistory != null) {

				for (final ServiceHistoryInstanceType serviceHistoryItem : serviceHistory.getServiceHistoryInstance()) {

					final HistoricalTrustService historicalService = new HistoricalTrustService(serviceHistoryItem);
					trustServiceList.add(historicalService);
				}
			}

			// The Services must be sorted in descending order CROBIES 2.2.15
			// TODO: (Bob: 2014 Feb 21) The TSL is already sorted. To be removed
			Collections.sort(trustServiceList, new Comparator<AbstractTrustService>() {

				@Override
				public int compare(AbstractTrustService o1, AbstractTrustService o2) {

					return -o1.getStatusStartDate().compareTo(o2.getStatusStartDate());
				}
			});

			AbstractTrustService previous = currentService;
			for (AbstractTrustService trustService : trustServiceList) {

				if (trustService instanceof HistoricalTrustService) {

					((HistoricalTrustService) trustService).setPreviousEntry(previous);
				}
				previous = trustService;
			}
			providerList.addAll(trustServiceList);
		}
		return providerList;
	}

	private String getEnglishOrFirst(InternationalNamesType names) {

		if (names == null) {
			return null;
		}
		for (MultiLangNormStringType s : names.getName()) {
			if ("en".equalsIgnoreCase(s.getLang())) {
				return s.getValue();
			}
		}
		return names.getName().get(0).getValue();
	}

	public String getName() {

		return getEnglishOrFirst(tspType.getTSPInformation().getTSPName());
	}

	public String getTradeName() {

		return getEnglishOrFirst(tspType.getTSPInformation().getTSPTradeName());
	}

	public String getPostalAddress() {

		PostalAddressType a = null;
		if (tspType.getTSPInformation().getTSPAddress() == null) {
			return null;
		}
		for (PostalAddressType c : tspType.getTSPInformation().getTSPAddress().getPostalAddresses().getPostalAddress()) {
			if ("en".equalsIgnoreCase(c.getLang())) {
				a = c;
				break;
			}
		}
		if (a == null) {
			a = tspType.getTSPInformation().getTSPAddress().getPostalAddresses().getPostalAddress().get(0);
		}
		return a.getStreetAddress() + ", " + a.getPostalCode() + " " + a.getLocality() + ", " + a.getStateOrProvince() + a.getCountryName();
	}

	public String getElectronicAddress() {

		if (tspType.getTSPInformation().getTSPAddress().getElectronicAddress() == null) {
			return null;
		}
		return tspType.getTSPInformation().getTSPAddress().getElectronicAddress().getURI().get(0).getValue();
	}
}