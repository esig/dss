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
package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Set;

/**
 * Verifies whether acceptable Trusted Lists have been found
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class AcceptableTrustedListPresenceCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Set of URLs of acceptable Trusted Lists */
	private final Set<String> validTLUrls;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param validTLUrls a set of URL {@link String}s of acceptable Trusted Lists
	 * @param constraint {@link LevelConstraint}
	 */
	public AcceptableTrustedListPresenceCheck(I18nProvider i18nProvider, T result, Set<String> validTLUrls,
											  LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.validTLUrls = validTLUrls;
	}

	@Override
	public boolean process() {
		return Utils.isCollectionNotEmpty(validTLUrls);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT_ANS;
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