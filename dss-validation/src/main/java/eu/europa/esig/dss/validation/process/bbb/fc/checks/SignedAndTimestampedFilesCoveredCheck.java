package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

/**
 * This class checks whether all files signed by the covered signatures or timestamped by covered timestamps
 * are covered by the current timestamp as well
 *
 */
public class SignedAndTimestampedFilesCoveredCheck extends AbstractSignedAndTimestampedFilesCoveredCheck<XmlFC> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param containerInfo {@link XmlContainerInfo}
     * @param timestampWrapper {@link TimestampWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public SignedAndTimestampedFilesCoveredCheck(I18nProvider i18nProvider, XmlFC result, XmlContainerInfo containerInfo,
                                                 TimestampWrapper timestampWrapper, LevelConstraint constraint) {
        super(i18nProvider, result, containerInfo, timestampWrapper.getFilename(), constraint);
    }

}
