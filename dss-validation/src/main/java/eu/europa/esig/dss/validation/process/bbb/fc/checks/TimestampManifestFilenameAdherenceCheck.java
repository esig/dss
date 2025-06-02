package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;

/**
 * Verifies conformance of a related to a timestamp manifest filename
 *
 */
public class TimestampManifestFilenameAdherenceCheck extends FilenameAdherenceCheck<TimestampWrapper> {

    /** The ASiC Archive Manifest name */
    protected static final String LAST_ARCHIVE_MANIFEST_FILENAME = META_INF_FOLDER + ARCHIVE_MANIFEST_FILENAME + XML_EXTENSION;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param result         {@link XmlFC}
     * @param diagnosticData {@link DiagnosticData}
     * @param token          {@link TimestampWrapper}
     * @param constraint     {@link LevelRule}
     */
    public TimestampManifestFilenameAdherenceCheck(I18nProvider i18nProvider, XmlFC result, DiagnosticData diagnosticData,
                                           TimestampWrapper token, LevelRule constraint) {
        super(i18nProvider, result, diagnosticData, token, constraint);
    }

    @Override
    protected boolean process() {
        if (ASiCContainerType.ASiC_S == diagnosticData.getContainerType()) {
            /*
             * 4.3.3.2 Contents of the container
             *
             * The ASiC-S container:
             * 5) The META-INF folder may contain the following additional files:
             * c) Other application specific information.
             */
            return true; // TODO : can be of any format ?
        }

        XmlManifestFile manifestFile = diagnosticData.getManifestFileForFilename(token.getFilename());
        if (manifestFile == null) {
            return false; // required for a timestamp
        }

        String manifestFilename = manifestFile.getFilename();
        if (Utils.isStringEmpty(manifestFilename)) {
            return false;
        }

        if (coversArchivalContent(manifestFile)) {
            return isLastArchivalTimestamp() ? LAST_ARCHIVE_MANIFEST_FILENAME.equals(manifestFilename) : isASiCArchiveManifest(manifestFilename);
        } else {
            return isASiCManifest(manifestFilename);
        }
    }

    private boolean coversArchivalContent(XmlManifestFile manifestFile) {
        return manifestFile.getEntries().stream().anyMatch(m -> m.startsWith(META_INF_FOLDER) &&
                (m.contains(SIGNATURE_FILENAME) || m.contains(TIMESTAMP_FILENAME) || m.contains(EVIDENCE_RECORD_FILENAME)));
    }

    private boolean isLastArchivalTimestamp() {
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (timestampWrapper.getFilename() != null && !timestampWrapper.getFilename().equals(token.getFilename())) {
                XmlManifestFile tstManifest = diagnosticData.getManifestFileForFilename(timestampWrapper.getFilename());
                if (coversFilename(tstManifest, token.getFilename())) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean coversFilename(XmlManifestFile manifestFile, String filename) {
        return manifestFile != null && manifestFile.getEntries().stream().anyMatch(e -> e.equals(filename));
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_IMFCS;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_IMFCS_ANS;
    }

}
