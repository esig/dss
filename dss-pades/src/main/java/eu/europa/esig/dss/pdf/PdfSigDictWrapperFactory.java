package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.ByteRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;

/**
 * This class creates a {@code PdfSigDictWrapper} instance
 * 
 */
public class PdfSigDictWrapperFactory {

    private static final Logger LOG = LoggerFactory.getLogger(PdfSigDictWrapperFactory.class);

    /** PDF dictionary representing the signature field */
    private final PdfDict sigFieldDictionary;

    /**
     * Default constructor
     *
     * @param sigFieldDictionary {@link PdfDict} representing the signature field dictionary
     */
    public PdfSigDictWrapperFactory(final PdfDict sigFieldDictionary) {
        this.sigFieldDictionary = sigFieldDictionary;
    }

    /**
     * Creates a new {@code PdfSigDictWrapper}
     *
     * @return {@link PdfSigDictWrapper}
     */
    public PdfSigDictWrapper create() {
        final PdfSigDictWrapper pdfSigDictWrapper = new PdfSigDictWrapper();
        pdfSigDictWrapper.setDictionary(sigFieldDictionary);
        pdfSigDictWrapper.setCMS(buildCMS());
        pdfSigDictWrapper.setSignerName(getSignerName());
        pdfSigDictWrapper.setSigningDate(getSigningDate());
        pdfSigDictWrapper.setContactInfo(getContactInfo());
        pdfSigDictWrapper.setReason(getReason());
        pdfSigDictWrapper.setLocation(getLocation());
        pdfSigDictWrapper.setSigningDate(getSigningDate());
        pdfSigDictWrapper.setType(getType());
        pdfSigDictWrapper.setFilter(getFilter());
        pdfSigDictWrapper.setSubFilter(getSubFilter());
        pdfSigDictWrapper.setContents(getContents());
        pdfSigDictWrapper.setByteRange(getByteRange());
        pdfSigDictWrapper.setDocMDP(getDocMDP());
        pdfSigDictWrapper.setFieldMDP(getFieldMDP());
        return pdfSigDictWrapper;
    }

    private CMS buildCMS() {
        return CMSUtils.parseToCMS(getContents());
    }

    private String getSignerName() {
        return sigFieldDictionary.getStringValue(PAdESConstants.NAME_NAME);
    }

    private String getContactInfo() {
        return sigFieldDictionary.getStringValue(PAdESConstants.CONTACT_INFO_NAME);
    }

    private String getReason() {
        return sigFieldDictionary.getStringValue(PAdESConstants.REASON_NAME);
    }

    private String getLocation() {
        return sigFieldDictionary.getStringValue(PAdESConstants.LOCATION_NAME);
    }

    private Date getSigningDate() {
        return sigFieldDictionary.getDateValue(PAdESConstants.SIGNING_DATE_NAME);
    }

    private String getType() {
        return sigFieldDictionary.getNameValue(PAdESConstants.TYPE_NAME);
    }

    private String getFilter() {
        return sigFieldDictionary.getNameValue(PAdESConstants.FILTER_NAME);
    }

    private String getSubFilter() {
        return sigFieldDictionary.getNameValue(PAdESConstants.SUB_FILTER_NAME);
    }

    private byte[] getContents() {
        try {
            return sigFieldDictionary.getBinariesValue(PAdESConstants.CONTENTS_NAME);
        } catch (IOException e) {
            throw new DSSException("Unable to retrieve the signature content", e);
        }
    }

    private ByteRange getByteRange() {
        PdfArray byteRangeArray = sigFieldDictionary.getAsArray(PAdESConstants.BYTE_RANGE_NAME);
        if (byteRangeArray == null) {
            throw new DSSException(String.format("Unable to retrieve the '%s' field value.", PAdESConstants.BYTE_RANGE_NAME));
        }

        int arraySize = byteRangeArray.size();
        int[] result = new int[arraySize];
        for (int i = 0; i < arraySize; i++) {
            result[i] = byteRangeArray.getNumber(i).intValue();
        }
        return new ByteRange(result);
    }

    private CertificationPermission getDocMDP() {
        PdfArray referenceArray = sigFieldDictionary.getAsArray(PAdESConstants.REFERENCE_NAME);
        if (referenceArray != null) {
            for (int i = 0; i < referenceArray.size(); i++) {
                PdfDict sigRef = referenceArray.getAsDict(i);
                if (PAdESConstants.DOC_MDP_NAME.equals(sigRef.getNameValue(PAdESConstants.TRANSFORM_METHOD_NAME))) {
                    PdfDict transformParams = sigRef.getAsDict(PAdESConstants.TRANSFORM_PARAMS_NAME);
                    if (transformParams == null) {
                        LOG.warn("No '{}' dictionary found. Unable to perform a '{}' entry validation!",
                                PAdESConstants.TRANSFORM_PARAMS_NAME, PAdESConstants.DOC_MDP_NAME);
                        continue;
                    }
                    Number permissions = transformParams.getNumberValue(PAdESConstants.PERMISSIONS_NAME);
                    if (permissions == null) {
                        LOG.warn("No '{}' parameter found. Unable to perform a '{}' entry validation!",
                                PAdESConstants.PERMISSIONS_NAME, PAdESConstants.DOC_MDP_NAME);
                        continue;
                    }
                    return CertificationPermission.fromCode(permissions.intValue());
                }
            }
        }
        return null;
    }

    private SigFieldPermissions getFieldMDP() {
        PdfArray referenceArray = sigFieldDictionary.getAsArray(PAdESConstants.REFERENCE_NAME);
        if (referenceArray != null) {
            for (int i = 0; i < referenceArray.size(); i++) {
                PdfDict sigRef = referenceArray.getAsDict(i);
                if (PAdESConstants.FIELD_MDP_NAME.equals(sigRef.getNameValue(PAdESConstants.TRANSFORM_METHOD_NAME))) {
                    PdfDict dataDict = sigRef.getAsDict(PAdESConstants.DATA_NAME);
                    if (dataDict == null) {
                        LOG.warn("No '{}' dictionary found. Unable to perform a '{}' entry validation!",
                                PAdESConstants.DATA_NAME, PAdESConstants.FIELD_MDP_NAME);
                        continue;
                    }
                    String dataDictType = dataDict.getNameValue(PAdESConstants.TYPE_NAME);
                    if (!PAdESConstants.CATALOG_NAME.equals(dataDictType)) {
                        LOG.warn("Unsupported type of '{}' dictionary found : '{}'. The '{}' validation skipped.",
                                PAdESConstants.DATA_NAME, dataDictType, PAdESConstants.FIELD_MDP_NAME);
                        continue;
                    }
                    PdfDict transformParams = sigRef.getAsDict(PAdESConstants.TRANSFORM_PARAMS_NAME);
                    if (transformParams == null) {
                        LOG.warn("No '{}' dictionary found. Unable to perform a '{}' entry validation!",
                                PAdESConstants.TRANSFORM_PARAMS_NAME, PAdESConstants.FIELD_MDP_NAME);
                        continue;
                    }
                    return PAdESUtils.extractPermissionsDictionary(transformParams);
                }
            }
        }
        return null;
    }
    
}
