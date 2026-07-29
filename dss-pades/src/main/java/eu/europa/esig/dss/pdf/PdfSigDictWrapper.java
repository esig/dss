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

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.modifications.ObjectModification;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModifications;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The default implementation of {@code PdfSignatureDictionary}
 */
public class PdfSigDictWrapper implements PdfSignatureDictionary {

	private static final Logger LOG = LoggerFactory.getLogger(PdfSigDictWrapper.class);

	/** The original PDF dictionary */
	private PdfDict dictionary;

	/** Name of the signer */
	private String signerName;

	/** Contact info of the signer */
	private String contactInfo;

	/** Reason of signing */
	private String reason;

	/** Location of signing */
	private String location;

	/** The datetime of signing */
	private Date signingDate;

	/** The type of the dictionary */
	private String type;

	/** Value of the /Filter parameter */
	private String filter;

	/** Value of the /SubFilter parameter */
	private String subFilter;

	/** Value of the /Contents signature parameter */
	private byte[] contents;

	/** Value of the /ByteRange parameter */
	private ByteRange byteRange;

	/** Value of the /DocMDP parameter */
	private CertificationPermission docMDP;

	/** Value of the /FieldMDP parameter */
	private SigFieldPermissions fieldMDP;

	/** CMS signature value */
	private CMS cms;

	/** Identifies whether the signature dictionary is consistent between revisions */
	private boolean consistent;

	/**
	 * Keys of a signature field's dictionary to be checked during a field-level consistency comparison.
	 * We check only /Rect and /AP because they are the main keys responsible for
	 * visually altering the field. Although it would be possible to check the other keys, we prefer to adopt a conservative approach given implementation behavior can differ between PdfBox and OpenPDF.
	 */
	private static final Set<String> SIGNATURE_FIELD_CHECKED_KEYS = new HashSet<>(Arrays.asList(
			PAdESConstants.RECT_NAME, PAdESConstants.APPEARANCE_DICTIONARY_NAME));

	/**
	 * Keys of a signature dictionary to be skipped during a signature-dictionary-level consistency comparison.
	 * /Reference is handled separately (see {@link #REFERENCE_ENTRY_IGNORED_KEYS}), since its entries' /Data key
	 * points at the document Catalog.
	 */
	private static final Set<String> SIGNATURE_DICT_IGNORED_KEYS = Collections.singleton(PAdESConstants.REFERENCE_NAME);

	/**
	 * Keys of a /Reference entry to be skipped during a reference-entry-level consistency comparison.
	 * /Data points directly at the document Catalog.
	 */
	private static final Set<String> REFERENCE_ENTRY_IGNORED_KEYS = Collections.singleton(PAdESConstants.DATA_NAME);

	/**
	 * Default constructor
	 */
	protected PdfSigDictWrapper() {
		// empty
	}

	/**
	 * Sets the signature field dictionary
	 *
	 * @param dictionary {@link PdfDict}
	 */
	protected void setDictionary(PdfDict dictionary) {
		this.dictionary = dictionary;
	}

	@Override
	public String getSignerName() {
		return signerName;
	}

	/**
	 * Sets the name of the signer
	 *
	 * @param signerName {@link String}
	 */
	protected void setSignerName(String signerName) {
		this.signerName = signerName;
	}

	@Override
	public String getContactInfo() {
		return contactInfo;
	}

	/**
	 * Sets the contact info
	 *
	 * @param contactInfo {@link String}
	 */
	protected void setContactInfo(String contactInfo) {
		this.contactInfo = contactInfo;
	}

	@Override
	public String getReason() {
		return reason;
	}

	/**
	 * Sets the signing reason
	 *
	 * @param reason {@link String}
	 */
	protected void setReason(String reason) {
		this.reason = reason;
	}

	@Override
	public String getLocation() {
		return location;
	}

	/**
	 * Sets the signer location
	 *
	 * @param location {@link String}
	 */
	protected void setLocation(String location) {
		this.location = location;
	}

	@Override
	public Date getSigningDate() {
		return signingDate;
	}

	/**
	 * Sets the date of signing
	 *
	 * @param signingDate {@link Date}
	 */
	protected void setSigningDate(Date signingDate) {
		this.signingDate = signingDate;
	}

	@Override
	public String getType() {
		return type;
	}

	/**
	 * Sets the type of the dictionary
	 *
	 * @param type {@link String}
	 */
	protected void setType(String type) {
		this.type = type;
	}

	@Override
	public String getFilter() {
		return filter;
	}

	/**
	 * Sets the /Filter value
	 *
	 * @param filter {@link String}
	 */
	protected void setFilter(String filter) {
		this.filter = filter;
	}

	@Override
	public String getSubFilter() {
		return subFilter;
	}

	/**
	 * Sets the /SubFilter value
	 *
	 * @param subFilter {@link String}
	 */
	protected void setSubFilter(String subFilter) {
		this.subFilter = subFilter;
	}

	@Override
	public byte[] getContents() {
		return contents;
	}

	/**
	 * Sets the /Contents signature value
	 *
	 * @param contents byte array
	 */
	protected void setContents(byte[] contents) {
		this.contents = contents;
	}

	@Override
	public ByteRange getByteRange() {
		return byteRange;
	}

	/**
	 * Sets the /ByteRange value
	 *
	 * @param byteRange {@link ByteRange}
	 */
	protected void setByteRange(ByteRange byteRange) {
		this.byteRange = byteRange;
	}

	@Override
	public CertificationPermission getDocMDP() {
		return docMDP;
	}

	/**
	 * Sets the /DocMPD dictionary value
	 *
	 * @param docMDP {@link CertificationPermission}
	 */
	protected void setDocMDP(CertificationPermission docMDP) {
		this.docMDP = docMDP;
	}

	@Override
	public SigFieldPermissions getFieldMDP() {
		return fieldMDP;
	}

	/**
	 * Sets the /FieldMDP dictionary value
	 *
	 * @param fieldMDP {@link SigFieldPermissions}
	 */
	protected void setFieldMDP(SigFieldPermissions fieldMDP) {
		this.fieldMDP = fieldMDP;
	}

	@Override
	public CMS getCMS() {
		return cms;
	}

	/**
	 * Sets the CMS value read from /Contents
	 *
	 * @param cms {@link CMS}
	 */
	protected void setCMS(CMS cms) {
		this.cms = cms;
	}

	@Override
	public boolean checkConsistency(List<PdfSignatureField> finalSignatureFields, PdfSignatureDictionary revisionSignatureDictionary,
									 List<PdfSignatureField> revisionSignatureFields) {
		consistent = false;

		if (revisionSignatureDictionary == null) {
			LOG.warn("PdfSignatureDictionary from signed revision is null!");

		} else if (finalSignatureFields == null || revisionSignatureFields == null
				|| finalSignatureFields.size() != revisionSignatureFields.size()) {
			LOG.warn("The number of signature fields does not match between the final and signed revisions!");

		} else if (revisionSignatureDictionary instanceof PdfSigDictWrapper) {
			PdfSigDictWrapper revisionSigDictWrapper = (PdfSigDictWrapper) revisionSignatureDictionary;
			DefaultPdfObjectModificationsFinder modificationsFinder = new DefaultPdfObjectModificationsFinder();

			if (checkSigDictConsistency(modificationsFinder, revisionSigDictWrapper.dictionary, this.dictionary)) {
				boolean allFieldsConsistent = true;
				for (PdfSignatureField finalSignatureField : finalSignatureFields) {
					PdfSignatureField revisionSignatureField = getSignatureFieldByName(
							revisionSignatureFields, finalSignatureField.getFullyQualifiedName());
					if (!checkFieldConsistency(modificationsFinder, finalSignatureField, revisionSignatureField)) {
						allFieldsConsistent = false;
						break;
					}
				}
				consistent = allFieldsConsistent;

			} else {
				LOG.warn("The signature dictionary from final PDF revision is not equal to the signed revision version!");
			}

		} else {
			LOG.warn("Provided PdfSignatureDictionary shall be instance of PdfSigDictWrapper!");
		}

		return consistent;
	}

	private PdfSignatureField getSignatureFieldByName(List<PdfSignatureField> signatureFields, String fullyQualifiedName) {
		for (PdfSignatureField signatureField : signatureFields) {
			if (Objects.equals(fullyQualifiedName, signatureField.getFullyQualifiedName())) {
				return signatureField;
			}
		}
		return null;
	}

	private boolean checkFieldConsistency(DefaultPdfObjectModificationsFinder modificationsFinder,
										  PdfSignatureField finalSignatureField, PdfSignatureField revisionSignatureField) {
		if (revisionSignatureField == null) {
			LOG.warn("No matching signature field '{}' found in the signed revision!", finalSignatureField.getFullyQualifiedName());
			return false;
		}

		PdfDict revisionDict = revisionSignatureField.getDictionary();
		PdfDict finalDict = finalSignatureField.getDictionary();

		boolean fieldConsistent = true;
		for (String key : SIGNATURE_FIELD_CHECKED_KEYS) {
			PdfObjectModifications pdfObjectModifications = modificationsFinder.find(
					key, revisionDict.getObject(key), finalDict.getObject(key));
			if (Utils.isCollectionNotEmpty(pdfObjectModifications.getUndefinedChanges())) {
				fieldConsistent = false;
				break;
			}
		}

		if (!fieldConsistent) {
			LOG.warn("The signature field '{}' from final PDF revision is not equal to the signed revision version!",
					finalSignatureField.getFullyQualifiedName());
		}
		return fieldConsistent;
	}

	private boolean checkSigDictConsistency(DefaultPdfObjectModificationsFinder modificationsFinder,
											PdfDict revisionSigDict, PdfDict finalSigDict) {
		if (!areKeysConsistent(modificationsFinder, revisionSigDict, finalSigDict, SIGNATURE_DICT_IGNORED_KEYS)) {
			return false;
		}

		PdfArray revisionReferences = revisionSigDict.getAsArray(PAdESConstants.REFERENCE_NAME);
		PdfArray finalReferences = finalSigDict.getAsArray(PAdESConstants.REFERENCE_NAME);
		int revisionSize = revisionReferences != null ? revisionReferences.size() : 0;
		int finalSize = finalReferences != null ? finalReferences.size() : 0;
		if (revisionSize != finalSize) {
			LOG.warn("The number of /Reference entries does not match between the final and signed revisions!");
			return false;
		}

		for (int i = 0; i < revisionSize; i++) {
			PdfDict revisionReference = revisionReferences.getAsDict(i);
			PdfDict finalReference = finalReferences.getAsDict(i);
			if (!areKeysConsistent(modificationsFinder, revisionReference, finalReference, REFERENCE_ENTRY_IGNORED_KEYS)) {
				return false;
			}
		}
		return true;
	}

	private boolean areKeysConsistent(DefaultPdfObjectModificationsFinder modificationsFinder, PdfDict revisionDict,
									  PdfDict finalDict, Set<String> ignoredKeys) {
		
		if (revisionDict == null && finalDict == null)
			return true;
		if (revisionDict == null || finalDict == null)
			return false;

		Set<String> keys = new LinkedHashSet<>();
		keys.addAll(Arrays.asList(revisionDict.list()));
		keys.addAll(Arrays.asList(finalDict.list()));
		for (String key : keys) {
			if (ignoredKeys.contains(key)) {
				continue;
			}
			PdfObjectModifications pdfObjectModifications = modificationsFinder.find(
					key, revisionDict.getObject(key), finalDict.getObject(key));
			List<ObjectModification> undefinedChanges = pdfObjectModifications.getUndefinedChanges();
			if (Utils.isCollectionNotEmpty(undefinedChanges)) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Undefined modifications for key '{}' are : {}", key, undefinedChanges.stream().map(ObjectModification::getObjectTree).collect(Collectors.toList()));
				}
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean isConsistent() {
		return consistent;
	}

}
