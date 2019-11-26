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
package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.IMessageTag;
import eu.europa.esig.dss.validation.process.MessageTag;

public class ManifestEntryExistenceCheck extends ChainItem<XmlCV> {

	private final List<XmlDigestMatcher> digestMatchers;

	public ManifestEntryExistenceCheck(XmlCV result, List<XmlDigestMatcher> digestMatchers, LevelConstraint constraint) {
		super(result, constraint);
		this.digestMatchers = digestMatchers;
	}

	@Override
	protected boolean process() {
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST_ENTRY.equals(xmlDigestMatcher.getType())) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected IMessageTag getMessageTag() {
		return MessageTag.BBB_CV_ISMEC;
	}

	@Override
	protected IMessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_ISMEC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIGNED_DATA_NOT_FOUND;
	}

}
