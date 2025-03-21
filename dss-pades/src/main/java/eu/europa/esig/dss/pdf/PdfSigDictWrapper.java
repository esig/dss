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
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.modifications.ObjectModification;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModifications;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;
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
	 * Default constructor
	 */
	protected PdfSigDictWrapper() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param dictionary {@link PdfDict}
	 * @deprecated since DSS 6.3. Please use {@code new PdfSigDictWrapperFactory(sigFieldDictionary)#create} instead
	 */
	@Deprecated
	public PdfSigDictWrapper(PdfDict dictionary) {
		PdfSigDictWrapper wrapper = new PdfSigDictWrapperFactory(dictionary).create();
		this.dictionary = wrapper.dictionary;
		this.signerName = wrapper.signerName;
		this.contactInfo = wrapper.contactInfo;
		this.reason = wrapper.reason;
		this.location = wrapper.location;
		this.signingDate = wrapper.signingDate;
		this.type = wrapper.type;
		this.filter = wrapper.filter;
		this.subFilter = wrapper.subFilter;
		this.contents = wrapper.contents;
		this.byteRange = wrapper.byteRange;
		this.docMDP = wrapper.docMDP;
		this.fieldMDP = wrapper.fieldMDP;
		this.cms = wrapper.cms;
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
