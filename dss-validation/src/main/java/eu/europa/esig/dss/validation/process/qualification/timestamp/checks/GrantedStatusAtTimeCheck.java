/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.timestamp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.List;

/**
 * Verifies of the certificate has related TrustServices which have been 'granted'
 * at the given validation time
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class GrantedStatusAtTimeCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** List of granted TrustServices at timestamp's production time */
	private final List<TrustServiceWrapper> trustServicesAtTime;

	/** Validation time of the TSP */
	private final ValidationTime validationTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param trustServicesAtTime list of {@link TrustServiceWrapper}s
	 * @param validationTime {@link ValidationTime} the validation time type
	 * @param constraint {@link LevelConstraint}
	 */
	public GrantedStatusAtTimeCheck(I18nProvider i18nProvider, T result, List<TrustServiceWrapper> trustServicesAtTime,
									ValidationTime validationTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.trustServicesAtTime = trustServicesAtTime;
		this.validationTime = validationTime;
	}

	@Override
	protected boolean process() {
		return Utils.isCollectionNotEmpty(trustServicesAtTime);
	}

	@Override
	protected XmlMessage buildConstraintMessage() {
		return buildXmlMessage(MessageTag.QUAL_HAS_GRANTED_AT, ValidationProcessUtils.getValidationTimeMessageTag(validationTime));
	}

	@Override
	protected XmlMessage buildErrorMessage() {
		return buildXmlMessage(MessageTag.QUAL_HAS_GRANTED_AT_ANS, ValidationProcessUtils.getValidationTimeMessageTag(validationTime));
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
