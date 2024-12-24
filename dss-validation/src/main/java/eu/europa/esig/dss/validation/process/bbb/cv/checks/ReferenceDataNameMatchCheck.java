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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the referenced document name matches the reference name
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class ReferenceDataNameMatchCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

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
    public ReferenceDataNameMatchCheck(I18nProvider i18nProvider, T result, XmlDigestMatcher digestMatcher, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.digestMatcher = digestMatcher;
    }

    @Override
    protected boolean process() {
        return digestMatcher.getUri() != null && digestMatcher.getUri().equals(digestMatcher.getDocumentName());
    }

    @Override
    protected MessageTag getMessageTag() {
        switch (digestMatcher.getType()) {
            case MANIFEST_ENTRY:
                return MessageTag.BBB_CV_DMENMND;
            default:
                return MessageTag.BBB_CV_DRNMND;
        }
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        switch (digestMatcher.getType()) {
            case MANIFEST_ENTRY:
                return MessageTag.BBB_CV_DMENMND_ANS;
            default:
                return MessageTag.BBB_CV_DRNMND_ANS;
        }
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.SIGNED_DATA_NOT_FOUND;
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.REFERENCE_NAME_CHECK, digestMatcher.getUri(), digestMatcher.getDocumentName());
    }

}
