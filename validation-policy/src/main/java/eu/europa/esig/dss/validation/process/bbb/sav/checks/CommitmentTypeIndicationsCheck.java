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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;

public class CommitmentTypeIndicationsCheck extends ChainItem<XmlSAV> {

	private final SignatureWrapper signature;
	private final MultiValuesConstraint constraint;

	public CommitmentTypeIndicationsCheck(I18nProvider i18nProvider, XmlSAV result, SignatureWrapper signature, MultiValuesConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.signature = signature;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {
		List<String> commitmentTypeIdentifiers = signature.getCommitmentTypeIdentifiers();
		List<String> expectedValues = constraint.getId();

		if (Utils.isCollectionEmpty(commitmentTypeIdentifiers)) {
			return false;
		}

		if (Utils.isCollectionNotEmpty(expectedValues)) {
			return expectedValues.containsAll(commitmentTypeIdentifiers);
		}

		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ISQPXTIP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ISQPXTIP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
