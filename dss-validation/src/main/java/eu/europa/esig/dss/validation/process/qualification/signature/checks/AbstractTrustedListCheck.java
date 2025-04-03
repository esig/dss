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
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Abstract class verifying the validity of the Trusted List
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public abstract class AbstractTrustedListCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Trusted List validation result */
	private final XmlTLAnalysis tlAnalysis;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion} result
	 * @param tlAnalysis {@link XmlTLAnalysis}
	 * @param constraint {@link LevelRule}
	 */
	protected AbstractTrustedListCheck(I18nProvider i18nProvider, T result, XmlTLAnalysis tlAnalysis, LevelRule constraint) {
		super(i18nProvider, result, constraint, tlAnalysis.getId());

		this.tlAnalysis = tlAnalysis;
	}

	@Override
	public boolean process() {
		return isValidConclusion(tlAnalysis.getConclusion());
	}

	@Override
	protected String buildAdditionalInfo() {
		return i18nProvider.getMessage(MessageTag.TRUSTED_LIST, tlAnalysis.getURL());
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
