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

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the referenced data is intact
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class ReferenceDataIntactCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** The reference DigestMatcher */
	private final XmlDigestMatcher digestMatcher;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlCV}
	 * @param digestMatcher {@link XmlDigestMatcher}
	 * @param constraint {@link LevelConstraint}
	 */
	public ReferenceDataIntactCheck(I18nProvider i18nProvider, T result, XmlDigestMatcher digestMatcher, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.digestMatcher = digestMatcher;
	}

	@Override
	protected boolean process() {
		return digestMatcher.isDataIntact();
	}

	@Override
	protected MessageTag getMessageTag() {
		switch (digestMatcher.getType()) {
			case MESSAGE_IMPRINT:
				return MessageTag.BBB_CV_TSP_IRDOI;
			case COUNTER_SIGNED_SIGNATURE_VALUE:
				return MessageTag.BBB_CV_CS_CSPS;
			case MANIFEST_ENTRY:
				return MessageTag.BBB_CV_IMEDOI;
			case EVIDENCE_RECORD_ARCHIVE_TIME_STAMP:
				return MessageTag.BBB_CV_ER_ATSRI;
			case EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE:
				return MessageTag.BBB_CV_ER_ATSSRI;
			default:
				return MessageTag.BBB_CV_IRDOI;
		}
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (digestMatcher.getType()) {
			case MESSAGE_IMPRINT:
				return MessageTag.BBB_CV_TSP_IRDOI_ANS;
			case COUNTER_SIGNED_SIGNATURE_VALUE:
				return MessageTag.BBB_CV_CS_CSPS_ANS;
			case MANIFEST_ENTRY:
				return MessageTag.BBB_CV_IMEDOI_ANS;
			case EVIDENCE_RECORD_ARCHIVE_TIME_STAMP:
				return MessageTag.BBB_CV_ER_ATSRI_ANS;
			case EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE:
				return MessageTag.BBB_CV_ER_ATSSRI_ANS;
			default:
				return MessageTag.BBB_CV_IRDOI_ANS;
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.HASH_FAILURE;
	}

	@Override
	protected String buildAdditionalInfo() {
		Object referenceName;
		switch (digestMatcher.getType()) {
			case MESSAGE_IMPRINT:
			case COUNTER_SIGNED_SIGNATURE_VALUE:
				return null;
			case EVIDENCE_RECORD_ARCHIVE_TIME_STAMP:
				referenceName = MessageTag.TST_TYPE_REF_ER_ATST;
				break;
			case EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE:
				referenceName = MessageTag.TST_TYPE_REF_ER_ATST_SEQ;
				break;
			default:
				referenceName = Utils.isStringNotBlank(digestMatcher.getId()) ? digestMatcher.getId() :
						Utils.isStringNotBlank(digestMatcher.getUri()) ? digestMatcher.getUri() :
								digestMatcher.getType().name();
		}
		return i18nProvider.getMessage(MessageTag.REFERENCE, referenceName);
	}

}
