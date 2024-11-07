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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.modifications.ObjectModification;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModifications;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The default implementation of {@code PdfSignatureDictionary}
 */
public class PdfSigDictWrapper implements PdfSignatureDictionary {

	private static final Logger LOG = LoggerFactory.getLogger(PdfSigDictWrapper.class);

	/** The PDF dictionary */
	private final PdfDict dictionary;

	/** The CMSSignedData */
	private final CMSSignedData cmsSignedData;

	/** The signed ByteRange */
	private final ByteRange byteRange;

	/** Identifies whether the signature dictionary is consistent between revisions */
	private boolean consistent;

	/**
	 * Default constructor
	 *
	 * @param dictionary {@link PdfDict}
	 */
	public PdfSigDictWrapper(PdfDict dictionary) {
		this.dictionary = dictionary;
		this.cmsSignedData = buildCMSSignedData();
		this.byteRange = buildByteRange();
	}

	private CMSSignedData buildCMSSignedData() {
		try {
			return new CMSSignedData(getContents());
		} catch (CMSException e) {
			throw new DSSException("Unable to build an instance of CMSSignedData", e);
		}
	}

	private ByteRange buildByteRange() {
		PdfArray byteRangeArray = dictionary.getAsArray(PAdESConstants.BYTE_RANGE_NAME);
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

	@Override
	public String getSignerName() {
		return dictionary.getStringValue(PAdESConstants.NAME_NAME);
	}

	@Override
	public String getContactInfo() {
		return dictionary.getStringValue(PAdESConstants.CONTACT_INFO_NAME);
	}

	@Override
	public String getReason() {
		return dictionary.getStringValue(PAdESConstants.REASON_NAME);
	}

	@Override
	public String getLocation() {
		return dictionary.getStringValue(PAdESConstants.LOCATION_NAME);
	}

	@Override
	public Date getSigningDate() {
		return dictionary.getDateValue(PAdESConstants.SIGNING_DATE_NAME);
	}

	@Override
	public String getType() {
		return dictionary.getNameValue(PAdESConstants.TYPE_NAME);
	}

	@Override
	public String getFilter() {
		return dictionary.getNameValue(PAdESConstants.FILTER_NAME);
	}

	@Override
	public String getSubFilter() {
		return dictionary.getNameValue(PAdESConstants.SUB_FILTER_NAME);
	}

	@Override
	public CMSSignedData getCMSSignedData() {
		return cmsSignedData;
	}

	@Override
	public byte[] getContents() {
		try {
			return dictionary.getBinariesValue(PAdESConstants.CONTENTS_NAME);
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the signature content", e);
		}
	}

	@Override
	public ByteRange getByteRange() {
		return byteRange;
	}

	@Override
	public CertificationPermission getDocMDP() {
		PdfArray referenceArray = dictionary.getAsArray(PAdESConstants.REFERENCE_NAME);
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

	@Override
	public SigFieldPermissions getFieldMDP() {
		PdfArray referenceArray = dictionary.getAsArray(PAdESConstants.REFERENCE_NAME);
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

	@Override
	public boolean checkConsistency(PdfSignatureDictionary signatureDictionary) {
		if (signatureDictionary == null) {
			LOG.warn("PdfSignatureDictionary from signed revision is null!");
			consistent = false;

		} else if (signatureDictionary instanceof PdfSigDictWrapper) {
			PdfSigDictWrapper dictionaryToCompare = (PdfSigDictWrapper) signatureDictionary;
			DefaultPdfObjectModificationsFinder modificationsFinder = new DefaultPdfObjectModificationsFinder();
			PdfObjectModifications pdfObjectModifications = modificationsFinder.find(dictionaryToCompare.dictionary, dictionary);
			List<ObjectModification> undefinedChanges = pdfObjectModifications.getUndefinedChanges();
			removeReferenceData(undefinedChanges);
			consistent = Utils.isCollectionEmpty(undefinedChanges);
			if (!consistent) {
				LOG.warn("The signature dictionary from final PDF revision is not equal to the signed revision version!");
				if (LOG.isDebugEnabled()) {
					LOG.debug("Undefined modifications are : {}", undefinedChanges.stream()
							.map(ObjectModification::getObjectTree).collect(Collectors.toList()));
				}
			}

		} else {
			LOG.warn("Provided PdfSignatureDictionary shall be instance of PdfSigDictWrapper!");
			consistent = false;
		}

		return consistent;
	}

	private void removeReferenceData(List<ObjectModification> modifications) {
		// /Reference /Data dictionary contains references to PDF objects covered by the signature.
		// The changes inside do not impact signature validity directly.
		if (Utils.isCollectionNotEmpty(modifications)) {
			modifications.removeIf(objectModification ->
					objectModification.getObjectTree().getKeyChain().contains(PAdESConstants.REFERENCE_NAME) &&
					objectModification.getObjectTree().getKeyChain().contains(PAdESConstants.DATA_NAME));
		}
	}

	@Override
	public boolean isConsistent() {
		return consistent;
	}

}
