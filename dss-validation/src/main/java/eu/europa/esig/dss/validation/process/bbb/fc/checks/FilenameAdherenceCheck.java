package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.AbstractSignatureWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies validity of the token's filename according to the ASiC's specification
 *
 * @param <T> {@code AbstractSignatureWrapper} implementation (signature or timestamp)
 */
public abstract class FilenameAdherenceCheck<T extends AbstractSignatureWrapper> extends ChainItem<XmlFC> {

    /** The META-INF folder */
    protected static final String META_INF_FOLDER = "META-INF/";

    /** The signature filename */
    protected static final String SIGNATURE_FILENAME = "signature";

    /** The timestamp filename */
    protected static final String TIMESTAMP_FILENAME = "timestamp";

    /** The evidence record filename */
    protected static final String EVIDENCE_RECORD_FILENAME = "evidencerecord";

    /** The ASiC Archive Manifest name */
    protected static final String ARCHIVE_MANIFEST_FILENAME = "ASiCArchiveManifest";

    /** The default XML manifest filename (META-INF/manifest.xml) */
    protected static final String ASICE_METAINF_MANIFEST = META_INF_FOLDER + "manifest.xml";

    /** The default ASiC manifest filename (META-INF/ASiCManifest*.xml) */
    protected static final String METAINF_ASIC_MANIFEST = META_INF_FOLDER + "ASiCManifest";

    /** The XML file extension */
    protected static final String XML_EXTENSION = ".xml";

    /** Token to be verified */
    protected final T token;

    /** Diagnostic data */
    protected final DiagnosticData diagnosticData;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param diagnosticData {@link DiagnosticData}
     * @param token {@link AbstractSignatureWrapper}
     * @param constraint {@link LevelRule}
     */
    protected FilenameAdherenceCheck(I18nProvider i18nProvider, XmlFC result, DiagnosticData diagnosticData, T token,
                                     LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.token = token;
        this.diagnosticData = diagnosticData;
    }

    /**
     * Checks if the filename corresponds to the "META-INF/ASiCManifest*.xml" pattern
     *
     * @param filename {@link String} to check
     * @return TRUE if the filename matches the ASiCManifest definition, FALSE otherwise
     */
    protected boolean isASiCManifest(String filename) {
        return filename.startsWith(METAINF_ASIC_MANIFEST) && filename.endsWith(XML_EXTENSION);
    }

    /**
     * Checks if the filename corresponds to the "META-INF/*ASiCArchiveManifest*.xml" pattern
     *
     * @param filename {@link String} to check
     * @return TRUE if the filename matches the ASiCArchiveManifest definition, FALSE otherwise
     */
    protected boolean isASiCArchiveManifest(String filename) {
        return filename.startsWith(META_INF_FOLDER) && filename.contains(ARCHIVE_MANIFEST_FILENAME) && filename.endsWith(XML_EXTENSION);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

}
