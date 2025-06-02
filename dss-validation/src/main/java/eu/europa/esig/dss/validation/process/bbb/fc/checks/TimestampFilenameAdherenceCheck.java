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
