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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustedServiceStatus;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustedServicesFilterFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Verifies if the certificate has TrustedServices with a 'granted' status
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class GrantedStatusCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** List of {@link TrustedServiceWrapper}s with a 'granted status' */
	private final List<TrustedServiceWrapper> trustServicesAtTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param trustServicesAtTime a list of {@link TrustedServiceWrapper}s
	 * @param constraint {@link LevelConstraint}
	 */
	public GrantedStatusCheck(I18nProvider i18nProvider, T result, 
			List<TrustedServiceWrapper> trustServicesAtTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.trustServicesAtTime = trustServicesAtTime;
	}

	@Override
	protected boolean process() {
		TrustedServiceFilter filterByGranted = TrustedServicesFilterFactory.createFilterByGranted();
		return Utils.isCollectionNotEmpty(filterByGranted.filter(trustServicesAtTime));
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_HAS_GRANTED;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_HAS_GRANTED_ANS;
	}

	@Override
	protected XmlMessage buildErrorMessage() {
		Collection<String> statusList = getStatusList();
		MessageTag errorTag = Utils.collectionSize(statusList) == 1 ? MessageTag.QUAL_HAS_GRANTED_ANS : MessageTag.QUAL_HAS_GRANTED_ANS_2;
		String argument = Utils.collectionSize(statusList) == 1 ? statusList.iterator().next() : statusList.toString();
		return buildXmlMessage(errorTag, argument);
	}

	private Collection<String> getStatusList() {
		Set<String> identifiers = new HashSet<>();
		for (TrustedServiceWrapper trustedService : trustServicesAtTime) {
			String status = trustedService.getStatus();
			TrustedServiceStatus tss = TrustedServiceStatus.fromUri(status);
			identifiers.add(tss != null ? tss.getShortName() : status);
		}
		return identifiers;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
