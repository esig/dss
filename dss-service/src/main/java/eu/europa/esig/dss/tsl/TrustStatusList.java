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
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.xml.datatype.XMLGregorianCalendar;

import eu.europa.esig.jaxb.tsl.NextUpdateType;
import eu.europa.esig.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.jaxb.tsl.TSPType;
import eu.europa.esig.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.esig.jaxb.tsl.TrustStatusListType;

/**
 * Represents a Trusted List
 *
 *
 */
class TrustStatusList {

	private TrustStatusListType trustStatusListType;

	private boolean wellSigned = false;

	/**
	 * The default constructor for TrustStatusList.
	 *
	 * @param trustStatusListType
	 */
	public TrustStatusList(TrustStatusListType trustStatusListType) {

		this.trustStatusListType = trustStatusListType;
	}

	/**
	 * @param wellSigned the wellSigned to set
	 */
	public void setWellSigned(boolean wellSigned) {

		this.wellSigned = wellSigned;
	}

	/**
	 * @return the wellSigned
	 */
	public boolean isWellSigned() {

		return wellSigned;
	}

	/**
	 * Returns the list of encapsulated providers.
	 *
	 * @return
	 */
	public List<TrustServiceProvider> getTrustServicesProvider() {

		final List<TrustServiceProvider> list = new ArrayList<TrustServiceProvider>();
		final TrustServiceProviderListType tspListType = trustStatusListType.getTrustServiceProviderList();
		if (tspListType != null) {

			final List<TSPType> tspTypes = tspListType.getTrustServiceProvider();
			for (final TSPType tsp : tspTypes) {

				list.add(new TrustServiceProvider(tsp));
			}
		}
		return list;
	}

	/**
	 * Returns the list of pointers to other TSL (with mime/type = application/vnd.etsi.tsl+xml)
	 *
	 * @return
	 */
	public List<PointerToOtherTSL> getOtherTSLPointers() {

		final List<PointerToOtherTSL> list = new ArrayList<PointerToOtherTSL>();

		final TSLSchemeInformationType tsiType = trustStatusListType.getSchemeInformation();
		if (tsiType != null) {

			final OtherTSLPointersType pointerListType = tsiType.getPointersToOtherTSL();
			if (pointerListType != null) {

				final List<OtherTSLPointerType> pointerTypes = pointerListType.getOtherTSLPointer();

				for (OtherTSLPointerType p : pointerTypes) {

					final PointerToOtherTSL pointer = new PointerToOtherTSL(p);
					if ("application/vnd.etsi.tsl+xml".equals(pointer.getMimeType())) {

						list.add(pointer);
					}
				}
			}
		}
		return list;
	}

	/**
	 * Returns the next update of the trusted list. This information can be used to implement an automatic TSL
	 * certificates reloader (based on {@link eu.europa.esig.dss.x509.CertificateSource}).
	 *
	 * @return
	 */
	public Date getNextUpdate() {

		final TSLSchemeInformationType schemeInformation = trustStatusListType.getSchemeInformation();
		if (schemeInformation != null) {

			final NextUpdateType nextUpdate = schemeInformation.getNextUpdate();
			if (nextUpdate != null) {
				final XMLGregorianCalendar gregorianCalendar = nextUpdate.getDateTime();
				if (gregorianCalendar != null) {
					final GregorianCalendar toGregorianCalendar = gregorianCalendar.toGregorianCalendar();
					if (toGregorianCalendar != null) {
						return toGregorianCalendar.getTime();
					}
				}
			}
		}
		return null;
	}
}
