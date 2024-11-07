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
package eu.europa.esig.dss.validation.process.qualification.trust.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Checks whether the version of the Trusted List is acceptable
 *
 */
public class TLVersionCheck extends ChainItem<XmlTLAnalysis> {

	private static final Logger LOG = LoggerFactory.getLogger(TLVersionCheck.class);

	/** Trusted List to check */
	private final XmlTrustedList currentTL;

	/** Validation time */
	private final Date currentTime;

	/** Constraint defining the acceptable version number */
	private final ValueConstraint constraint;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlTLAnalysis}
	 * @param currentTl {@link XmlTrustedList}
	 * @param currentTime {@link Date}
	 * @param constraint {@link ValueConstraint}
	 */
	public TLVersionCheck(I18nProvider i18nProvider, XmlTLAnalysis result, XmlTrustedList currentTl, Date currentTime,
						  ValueConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.currentTL = currentTl;
		this.currentTime = currentTime;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {

		if (!EIDASUtils.isPostGracePeriod(currentTime)) {
			return true;
		}

		String expectedVersionString = constraint.getValue();
		int version = 5; // default eIDAS
		try {
			version = Integer.parseInt(expectedVersionString);
		} catch (NumberFormatException e) {
			LOG.warn("Unable to parse TLVersion constraint : '{}'", expectedVersionString);
		}

		Integer tlVersion = currentTL.getVersion();
		return (tlVersion != null) && (tlVersion == version);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_VERSION;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TL_VERSION_ANS;
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
