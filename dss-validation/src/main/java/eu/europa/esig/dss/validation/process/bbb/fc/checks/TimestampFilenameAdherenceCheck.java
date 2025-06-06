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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class verifies conformance of the timestamp's document filename to the ASiC specification
 * 
 */
public class TimestampFilenameAdherenceCheck extends FilenameAdherenceCheck<TimestampWrapper> {

    /** The timestamp file extension */
    private static final String TST_EXTENSION = ".tst";

    /** The ASiC-S with CAdES timestamp document name (META-INF/timestamp.tst) */
    private static final String TIMESTAMP_TST = META_INF_FOLDER + TIMESTAMP_FILENAME + TST_EXTENSION;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param result         {@link XmlFC}
     * @param diagnosticData {@link DiagnosticData}
     * @param token          {@link TimestampWrapper}
     * @param constraint     {@link LevelRule}
     */
    public TimestampFilenameAdherenceCheck(I18nProvider i18nProvider, XmlFC result, DiagnosticData diagnosticData,
                                           TimestampWrapper token, LevelRule constraint) {
        super(i18nProvider, result, diagnosticData, token, constraint);
    }

    @Override
    protected boolean process() {
        String filename = token.getFilename();
        if (Utils.isStringEmpty(filename)) {
            return false;
        }
        switch (diagnosticData.getContainerType()) {
            case ASiC_S:
                return isInitialTimestampToken(filename) || isArchiveTimestampToken(filename);
            case ASiC_E:
                return isTimestamp(filename);
            default:
                throw new UnsupportedOperationException(String.format("Container type '%s' is not supported!", diagnosticData.getContainerType()));
        }
    }

    private boolean isInitialTimestampToken(String filename) {
        return TIMESTAMP_TST.equals(filename);
    }

    private boolean isArchiveTimestampToken(String filename) {
        XmlManifestFile manifestFile = diagnosticData.getManifestFileForFilename(filename);
        if (manifestFile != null && manifestFile.getFilename() != null && isASiCArchiveManifest(manifestFile.getFilename())) {
            return isTimestamp(filename);
        }
        return false;
    }

    private boolean isTimestamp(String filename) {
        return filename.startsWith(META_INF_FOLDER) && filename.contains(TIMESTAMP_FILENAME) && filename.endsWith(TST_EXTENSION);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_ISFCS;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_ISFCS_ANS;
    }

}
