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
package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Checks if at least one manifest entry is present
 *
 */
public class ManifestEntryExistenceCheck extends ChainItem<XmlCV> {

	/** The digest matchers to check */
	private final List<XmlDigestMatcher> digestMatchers;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlCV}
	 * @param digestMatchers a list of {@link XmlDigestMatcher}s
	 * @param constraint {@link LevelConstraint}
	 */
	public ManifestEntryExistenceCheck(I18nProvider i18nProvider, XmlCV result, List<XmlDigestMatcher> digestMatchers,
									   LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.digestMatchers = digestMatchers;
	}

	@Override
	protected boolean process() {
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST_ENTRY.equals(xmlDigestMatcher.getType()) && xmlDigestMatcher.isDataFound()) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_CV_ISMEC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		List<XmlDigestMatcher> manifestEntries = digestMatchers.stream().filter(d -> DigestMatcherType.MANIFEST_ENTRY == d.getType()).collect(Collectors.toList());
		if (Utils.isCollectionNotEmpty(manifestEntries) && manifestEntries.stream().noneMatch(XmlDigestMatcher::isDataFound)) {
			return MessageTag.BBB_CV_ISMEC_ANS_2;
		}
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
