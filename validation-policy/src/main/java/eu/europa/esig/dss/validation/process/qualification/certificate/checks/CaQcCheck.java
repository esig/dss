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

import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceTypeIdentifier;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServicesFilterFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Checks whether there are CA/QC TrustServices
 *
 */
public class CaQcCheck extends ChainItem<XmlValidationCertificateQualification> {

	/** List of {@code TrustServiceWrapper}s at control time */
	private final List<TrustServiceWrapper> trustServices;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationCertificateQualification}
	 * @param trustServices list of {@link TrustServiceWrapper}s
	 * @param constraint {@link LevelConstraint}
	 */
	public CaQcCheck(I18nProvider i18nProvider, XmlValidationCertificateQualification result,
					 List<TrustServiceWrapper> trustServices, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.trustServices = trustServices;
	}

	@Override
	protected boolean process() {
		TrustServiceFilter filterByCaQc = TrustServicesFilterFactory.createFilterByCaQc();
		return Utils.isCollectionNotEmpty(filterByCaQc.filter(trustServices));
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_HAS_CAQC;
	}

	@Override
	protected XmlMessage buildErrorMessage() {
		Collection<String> stiList = getStis();
		MessageTag errorTag = Utils.collectionSize(stiList) == 1 ? MessageTag.QUAL_HAS_CAQC_ANS : MessageTag.QUAL_HAS_CAQC_ANS_2;
		String argument = Utils.collectionSize(stiList) == 1 ? stiList.iterator().next() : stiList.toString();
		return buildXmlMessage(errorTag, argument);
	}
	
	private Collection<String> getStis() {
		Set<String> identifiers = new HashSet<>();
		for (TrustServiceWrapper trustService : trustServices) {
			String type = trustService.getType();
			ServiceTypeIdentifier sti = ServiceTypeIdentifier.fromUri(type);
			identifiers.add(sti != null ? sti.getShortName() : type);
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
