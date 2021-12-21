package eu.europa.esig.dss.asic.cades.timestamp;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * This class is used to create a timestamp covering signer files
 *
 */
public class ASiCWithCAdESTimestampService {

    /** TSPSource used to retrieve a timestamp response */
    private final TSPSource tspSource;

    /**
     * Default constructor
     *
     * @param tspSource {@link TSPSource}
     */
    public ASiCWithCAdESTimestampService(final TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    /**
     * The method is used to timestamp a list of {@code documents}
     *
     * @param documents a list of {@link DSSDocument}s
     * @param parameters {@link ASiCWithCAdESTimestampParameters}
     * @return {@link DSSDocument} timestamped archive
     */
    public DSSDocument timestamp(List<DSSDocument> documents, ASiCWithCAdESTimestampParameters parameters) {
        GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESTimestampDataToSignHelperBuilder()
                .build(documents, parameters);

        ASiCContent asicContent = createTimestampFromHelper(dataToSignHelper, parameters);
        return ZipUtils.getInstance().createZipArchive(asicContent, parameters.getZipCreationDate());
    }

    /**
     * This method is used to add a timestamp to the given {@code ASiCContent}
     * 
     * @param asicContent {@link ASiCContent} to timestamp signed documents from
     * @param parameters {@link ASiCWithCAdESTimestampParameters}
     * @return {@link ASiCContent} containing the timestamp and the related XML Manifest for ASiC-E container
     */
    public ASiCContent timestampASiCContent(ASiCContent asicContent, ASiCWithCAdESTimestampParameters parameters) {
        GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESTimestampDataToSignHelperBuilder()
                .buildFromASiCContent(asicContent, parameters);
        return createTimestampFromHelper(dataToSignHelper, parameters);
    }

    /**
     * This method creates a timestamp using {@code GetDataToSignASiCWithCAdESHelper}
     *
     * @param dataToSignHelper {@link GetDataToSignASiCWithCAdESHelper}
     * @param parameters {@link ASiCWithCAdESTimestampParameters}
     * @return {@link ASiCContent}
     */
    public ASiCContent createTimestampFromHelper(GetDataToSignASiCWithCAdESHelper dataToSignHelper,
                                                 ASiCWithCAdESTimestampParameters parameters) {
        ASiCContent asicContent = dataToSignHelper.getASiCContent();
        DSSDocument toBeTimestamped = dataToSignHelper.getToBeSigned();
        if (ASiCContainerType.ASiC_E == parameters.aSiC().getContainerType()) {
            asicContent.getManifestDocuments().add(toBeTimestamped); // XML Document in case of ASiC-E container
        }

        DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        TimestampBinary timestampBinary = tspSource.getTimeStampResponse(
                digestAlgorithm, Utils.fromBase64(toBeTimestamped.getDigest(digestAlgorithm)));

        DSSDocument timestampToken = new InMemoryDocument(
                DSSASN1Utils.getDEREncoded(timestampBinary), dataToSignHelper.getTimestampFilename(), MimeType.TST);
        ASiCUtils.addOrReplaceDocument(asicContent.getTimestampDocuments(), timestampToken);

        return asicContent;
    }

}
