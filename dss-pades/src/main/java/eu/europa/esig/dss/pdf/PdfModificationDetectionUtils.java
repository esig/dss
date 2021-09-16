/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.enumerations.PdfObjectModificationType;
import eu.europa.esig.dss.pades.validation.PdfModification;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The class contains utils for modification detection
 *
 */
public class PdfModificationDetectionUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PdfModificationDetectionUtils.class);

	private PdfModificationDetectionUtils() {
	}

	/**
	 * Returns a list of found annotation overlaps
	 * 
	 * @param reader {@link PdfDocumentReader} the complete PDF document reader
	 * @return a list of {@link PdfModification}s
	 * @throws IOException if an exception occurs
	 */
	public static List<PdfModification> getAnnotationOverlaps(PdfDocumentReader reader) throws IOException {
		List<PdfModification> annotationOverlaps = new ArrayList<>();

		for (int pageNumber = 1; pageNumber <= reader.getNumberOfPages(); pageNumber++) {
			List<PdfAnnotation> pdfAnnotations = reader.getPdfAnnotations(pageNumber);
			Iterator<PdfAnnotation> iterator = pdfAnnotations.iterator();
			while (iterator.hasNext()) {
				PdfAnnotation annotation = iterator.next();
				iterator.remove(); // remove the annotations from the comparison list
				if (isAnnotationBoxOverlapping(annotation.getAnnotationBox(), pdfAnnotations)) {
					annotationOverlaps.add(new CommonPdfModification(pageNumber));
					break;
				}
			}
		}

		return annotationOverlaps;
	}

	/**
	 * Checks if the given {@code annotationBox} overlaps with
	 * {@code otherAnnotations}
	 * 
	 * @param annotationBox  {@link AnnotationBox} to check
	 * @param pdfAnnotations a list of {@link PdfAnnotation} to validate against
	 * @return TRUE when {@code annotationBox} overlaps with at least one element
	 *         from {@code otherAnnotations} list, FALSE otherwise
	 */
	public static boolean isAnnotationBoxOverlapping(AnnotationBox annotationBox, List<PdfAnnotation> pdfAnnotations) {
		if (annotationBox.getWidth() == 0 || annotationBox.getHeight() == 0) {
			// invisible field
			return false;
		}
		for (PdfAnnotation pdfAnnotation : pdfAnnotations) {
			if (annotationBox.isOverlap(pdfAnnotation)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a list of visual differences found between signed and final revisions
	 * excluding newly created annotations
	 * 
	 * @param signedRevisionReader {@link PdfDocumentReader} for the signed
	 *                             (covered) revision content
	 * @param finalRevisionReader  {@link PdfDocumentReader} for the originally
	 *                             provided document
	 * @return a list of {@link PdfModification}s
	 * @throws IOException if an exception occurs
	 */
	public static List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
			PdfDocumentReader finalRevisionReader) throws IOException {
		List<PdfModification> visualDifferences = new ArrayList<>();

		for (int pageNumber = 1; pageNumber <= signedRevisionReader.getNumberOfPages()
				&& pageNumber <= finalRevisionReader.getNumberOfPages(); pageNumber++) {

			BufferedImage signedScreenshot = signedRevisionReader.generateImageScreenshot(pageNumber);

			List<PdfAnnotation> signedAnnotations = signedRevisionReader.getPdfAnnotations(pageNumber);
			List<PdfAnnotation> finalAnnotations = finalRevisionReader.getPdfAnnotations(pageNumber);

			List<PdfAnnotation> addedAnnotations = getUpdatedAnnotations(signedAnnotations, finalAnnotations);
			BufferedImage finalScreenshot = finalRevisionReader.generateImageScreenshotWithoutAnnotations(pageNumber,
					addedAnnotations);

			if (!ImageUtils.imagesEqual(signedScreenshot, finalScreenshot)) {
				LOG.warn("A visual difference found on page {} between a signed revision and the final document!",
						pageNumber);
				visualDifferences.add(new CommonPdfModification(pageNumber));
			}

		}

		return visualDifferences;
	}

	/**
	 * Returns a list of missing/added pages between signed and final revisions
	 * 
	 * @param signedRevisionReader {@link PdfDocumentReader} for the signed
	 *                             (covered) revision content
	 * @param finalRevisionReader  {@link PdfDocumentReader} for the originally
	 *                             provided document
	 * @return a list of {@link PdfModification}s
	 */
	public static List<PdfModification> getPagesDifferences(final PdfDocumentReader signedRevisionReader,
			final PdfDocumentReader finalRevisionReader) {
		int signedPages = signedRevisionReader.getNumberOfPages();
		int finalPages = finalRevisionReader.getNumberOfPages();

		int maxNumberOfPages = Math.max(signedPages, finalPages);
		int minNumberOfPages = Math.min(signedPages, finalPages);

		List<PdfModification> missingPages = new ArrayList<>();
		for (int ii = maxNumberOfPages; ii > minNumberOfPages; ii--) {
			missingPages.add(new CommonPdfModification(ii));
		}

		if (Utils.isCollectionNotEmpty(missingPages)) {
			LOG.warn("The provided PDF file contains {} additional pages against the signed revision!",
					maxNumberOfPages - minNumberOfPages);
		}

		return missingPages;
	}

	private static List<PdfAnnotation> getUpdatedAnnotations(List<PdfAnnotation> signedAnnotations,
			List<PdfAnnotation> finalAnnotations) {
		List<PdfAnnotation> updatesAnnotations = new ArrayList<>();
		for (PdfAnnotation annotationBox : finalAnnotations) {
			if (!signedAnnotations.contains(annotationBox)) {
				updatesAnnotations.add(annotationBox);
			}
		}
		return updatesAnnotations;
	}

	/**
	 * Extracts a set of object modifications
	 *
	 * @param signedRevisionReader {@link PdfDocumentReader} representing a signed revision
	 * @param finalRevisionReader {@link PdfDocumentReader} representing a final document revision
	 * @return a set of {@link ObjectModification}
	 */
	public static Set<ObjectModification> getModificationSet(final PdfDocumentReader signedRevisionReader,
															 final PdfDocumentReader finalRevisionReader) {
		final Set<ObjectModification> modifications = new LinkedHashSet<>(); // use LinkedHashSet in order to have a deteministic order

		final PdfDict signedCatalogDict = signedRevisionReader.getCatalogDictionary();
		final PdfDict finalCatalogDict = finalRevisionReader.getCatalogDictionary();
		compareDictsRecursively(modifications, new HashSet<>(), new PdfObjectTree(PAdESConstants.CATALOG_NAME),
				signedCatalogDict, finalCatalogDict);

		return modifications;
	}

	private static void compareDictsRecursively(Set<ObjectModification> modifications, Set<String> processedObjects,
												PdfObjectTree objectTree, PdfDict signedDict, PdfDict finalDict) {
		final String[] signedRevKeys = signedDict.list();
		final String[] finalRevKeys = finalDict.list();
		for (String key : signedRevKeys) {
			final PdfObjectTree currentObjectTree = objectTree.copy();
			Long objectNumber = signedDict.getObjectNumber(key);
			if (!isProcessedReference(processedObjects, currentObjectTree, key, objectNumber)) {
				currentObjectTree.addKey(key);
				addProcessedReference(processedObjects, currentObjectTree, key, objectNumber);
				compareObjectsRecursively(modifications, processedObjects, currentObjectTree, key,
						signedDict.getObject(key), finalDict.getObject(key));
			}
		}

		List<String> signedRevKeyList = Arrays.asList(signedRevKeys);
		for (String key : finalRevKeys) {
			final PdfObjectTree currentObjectTree = objectTree.copy();
			if (!signedRevKeyList.contains(key)) {
				currentObjectTree.addKey(key);
				Object finalObject = finalDict.getObject(key);
				if (finalObject instanceof PdfDict) {
					Long objectNumber = finalDict.getObjectNumber(key);
					addProcessedReference(processedObjects, currentObjectTree, key, objectNumber);
					modifications.add(ObjectModification.create(currentObjectTree, finalDict.getObject(key)));
					if (LOG.isDebugEnabled()) {
						LOG.debug("Added entry with key '{}'.", currentObjectTree);
					}
				} else {
					modifications.add(ObjectModification.modify(currentObjectTree, null, finalObject));
					if (LOG.isDebugEnabled()) {
						LOG.debug("Added parameter with key name '{}'.", objectTree);
					}
				}
			}
		}

		compareDictStreams(modifications, objectTree, signedDict, finalDict);
	}

	private static void compareObjectsRecursively(Set<ObjectModification> modifications, Set<String> processedObjects,
					PdfObjectTree objectTree, String key, Object signedObject, Object finalObject) {
		if (signedObject == null && finalObject != null) {
			if (finalObject instanceof PdfDict) {
				modifications.add(ObjectModification.create(objectTree, finalObject));
				if (LOG.isDebugEnabled()) {
					LOG.debug("Added entry with key '{}'.", objectTree);
				}
			} else {
				modifications.add(ObjectModification.modify(objectTree, null, finalObject));
				if (LOG.isDebugEnabled()) {
					LOG.debug("Added parameter with key name '{}'.", objectTree);
				}
			}

		} else if (signedObject != null && finalObject == null) {
			if (signedObject instanceof PdfDict) {
				modifications.add(ObjectModification.delete(objectTree, signedObject));
				if (LOG.isDebugEnabled()) {
					LOG.debug("Deleted entry with key '{}'.", objectTree);
				}
			} else {
				modifications.add(ObjectModification.modify(objectTree, signedObject, null));
				if (LOG.isDebugEnabled()) {
					LOG.debug("Deleted parameter with key name '{}'.", objectTree);
				}
			}

		} else if (signedObject != null && finalObject != null) {
			if (signedObject instanceof PdfDict && finalObject instanceof PdfDict) {
				compareDictsRecursively(modifications, processedObjects, objectTree,
						(PdfDict) signedObject, (PdfDict) finalObject);

			} else if (signedObject instanceof PdfArray && finalObject instanceof PdfArray) {
				PdfArray signedArray = (PdfArray) signedObject;
				PdfArray finalArray = (PdfArray) finalObject;
				compareArraysRecursively(modifications, processedObjects, objectTree, key,
						signedArray, finalArray, true);
				compareArraysRecursively(modifications, processedObjects, objectTree, key,
						finalArray, signedArray, false);

			} else if (signedObject instanceof String && finalObject instanceof String) {
				if (!signedObject.equals(finalObject)) {
					modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
					if (LOG.isDebugEnabled()) {
						LOG.debug("Object changed with key '{}'.", objectTree);
					}
				}

			} else if (signedObject instanceof Number && finalObject instanceof Number) {
				if (!signedObject.equals(finalObject)) {
					modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
					if (LOG.isDebugEnabled()) {
						LOG.debug("Object changed with key '{}'.", objectTree);
					}
				}

			} else if (signedObject instanceof Boolean && finalObject instanceof Boolean) {
				if (!signedObject.equals(finalObject)) {
					modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
					if (LOG.isDebugEnabled()) {
						LOG.debug("Object changed with key '{}'.", objectTree);
					}
				}

			} else {
				modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
				LOG.warn("Unsupported objects found with key '{}' of types '{}' and '{}'",
						objectTree, signedObject.getClass(), finalObject.getClass());
			}
		}
	}

	private static void compareArraysRecursively(Set<ObjectModification> modifications, Set<String> processedObjects,
					PdfObjectTree objectTree, String key, PdfArray firstArray, PdfArray secondArray, boolean signedFirst) {
		for (int i = 0; i < firstArray.size(); i++) {
			final PdfObjectTree currentObjectTree = objectTree.copy();

			Object signedRevObject = firstArray.getObject(i);
			Object finalRevObject = null;

			Long objectNumber = firstArray.getObjectNumber(i);
			if (objectNumber != null) {
				for (int j = 0; j < secondArray.size(); j++) {
					Long finalObjectNumber = secondArray.getObjectNumber(j);
					if (objectNumber.equals(finalObjectNumber)) {
						finalRevObject = secondArray.getObject(j);
					}
				}
			} else {
				finalRevObject = secondArray.getObject(i);
			}

			if (!isProcessedReference(processedObjects, currentObjectTree, key, objectNumber)) {
				addProcessedReference(processedObjects, currentObjectTree, key, objectNumber);
				compareObjectsRecursively(modifications, processedObjects, currentObjectTree, key,
						signedFirst ? signedRevObject : finalRevObject, signedFirst ? finalRevObject : signedRevObject);
			}
		}
	}

	private static boolean isProcessedReference(Set<String> processedObjects, PdfObjectTree objectTree,
												String key, Number objectNumber) {
		return processedObjects.contains(key + objectNumber) || objectTree.isProcessedReference(objectNumber);
	}

	private static void addProcessedReference(Set<String> processedObjects, PdfObjectTree objectTree,
											  String key, Number objectNumber) {
		if (objectNumber != null) {
			processedObjects.add(key + objectNumber);
			objectTree.addReference(objectNumber);
		}
	}

	private static void compareDictStreams(Set<ObjectModification> modifications, PdfObjectTree objectTree,
										   PdfDict signedDict, PdfDict finalDict) {
		final PdfObjectTree currentObjectTree = objectTree.copy();
		currentObjectTree.setStream();

		byte[] signedStream = getStreamBytesSecurely(signedDict);
		byte[] finalBytes = getStreamBytesSecurely(finalDict);
		if (Utils.isArrayEmpty(signedStream) && Utils.isArrayNotEmpty(finalBytes)) {
			modifications.add(ObjectModification.create(currentObjectTree, finalDict));
			if (LOG.isDebugEnabled()) {
				LOG.debug("A stream has been added '{}'.", currentObjectTree);
			}

		} else if (Utils.isArrayNotEmpty(signedStream) && Utils.isArrayEmpty(finalBytes)) {
			modifications.add(ObjectModification.delete(currentObjectTree, signedDict));
			if (LOG.isDebugEnabled()) {
				LOG.debug("A stream has been removed '{}'.", currentObjectTree);
			}

		} else if (Utils.isArrayNotEmpty(signedStream) && Utils.isArrayNotEmpty(finalBytes)) {
			if (!Arrays.equals(signedStream, finalBytes)) {
				modifications.add(ObjectModification.modify(currentObjectTree, signedDict, finalDict));
				if (LOG.isDebugEnabled()) {
					LOG.debug("A stream has been modified '{}'.", currentObjectTree);
				}
			}
		}
	}

	private static byte[] getStreamBytesSecurely(PdfDict pdfDict) {
		try {
			return pdfDict.getStreamBytes();

		} catch (IOException e) {
			String errorMessage = "Unable to compare underlying stream binaries. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}
	}

	/**
	 * This method is used to group a collection of {@code ObjectModification} by various security level categories
	 *
	 * @param objectModificationList a collection of {@link ObjectModification}s
	 * @return {@link PdfObjectModifications}
	 */
	public static PdfObjectModifications categorizeObjectModifications(Collection<ObjectModification> objectModificationList) {
		final PdfObjectModifications objectModifications = new PdfObjectModifications();

		for (ObjectModification objectModification : objectModificationList) {
			if (skipChange(objectModification)) {
				continue;
			}
			if (isSecureChange(objectModification)) {
				objectModifications.addSecureChange(objectModification);
			} else if (isFormFillAndSignatureCreationChange(objectModification)) {
				objectModifications.addFormFillInAndSignatureCreationChange(objectModification);
			} else if (isAnnotCreationChange(objectModification)) {
				objectModifications.addAnnotCreationChange(objectModification);
			} else {
				objectModifications.addUndefinedChange(objectModification);
			}
		}

		return objectModifications;
	}

	/*
	 * Note for developers:
	 * This method allows to skip some modification occurring in PdfBox and OpenPDF
	 */
	private static boolean skipChange(ObjectModification objectModification) {
		String lastKey = objectModification.getObjectTree().getLastKey();
		if (PdfObjectModificationType.DELETION.equals(objectModification.getActionType()) &&
				PAdESConstants.APPEARANCE_DICTIONARY_NAME.equals(lastKey)) {
			return true;
		} else if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
				PAdESConstants.ANNOT_FLAG.equals(lastKey)) {
			return true;
		} else if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
				PAdESConstants.TYPE_NAME.equals(lastKey)) {
			return true;
		} else if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
				PAdESConstants.ITEXT_NAME.equals(lastKey)) {
			return true;
		}
		return false;
	}

	private static boolean isSecureChange(ObjectModification objectModification) {
		if (isDSSDictionaryChange(objectModification)) {
			return true;
		} else if (isDocTimeStampAdded(objectModification)) {
			return true;
		} else if (isDocumentExtension(objectModification)) {
			return true;
		}
		return false;
	}

	private static boolean isDSSDictionaryChange(ObjectModification objectModification) {
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		for (String key : keyChain) {
			if (PAdESConstants.DSS_DICTIONARY_NAME.equals(key)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isDocTimeStampAdded(ObjectModification objectModification) {
		String key = objectModification.getObjectTree().getLastKey();
		if (isAnnotsKey(key)) {
			Object addedObject = objectModification.getFinalObject();
			if (addedObject instanceof PdfDict && isDocTimeStamp((PdfDict) addedObject)) {
				return true;
			}
			return false;
		}
		return false;
	}

	private static boolean isDocTimeStamp(PdfDict pdfDict) {
		final PdfDict vDict = pdfDict.getAsDict(PAdESConstants.VALUE_NAME);
		if (vDict != null) {
			String type = vDict.getNameValue(PAdESConstants.TYPE_NAME);
			if (PAdESConstants.TIMESTAMP_TYPE.equals(type)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isDocumentExtension(ObjectModification objectModification) {
		// can be relevant for /DSS or/and /DocTimeStamp incorporation
		String key = objectModification.getObjectTree().getLastKey();
		String parentKey = getParentKey(objectModification);
		return PAdESConstants.EXTENSIONS_NAME.equals(key) && PAdESConstants.CATALOG_NAME.equals(parentKey);
	}

	private static boolean isFormFillAndSignatureCreationChange(ObjectModification objectModification) {
		if (isFieldFilled(objectModification)) {
			return true;
		} else if (isAnnotsFill(objectModification)) {
			return true;
		} else if (isFieldAppearanceCreationChange(objectModification)) {
			return true;
		} else if (isMetaDataChange(objectModification)) {
			return true;
		} else if (isCatalogVersionChange(objectModification)) {
			return true;
		} else if (isCatalogExtensionsChange(objectModification)) {
			return true;
		} else if (isCatalogPieceInfoChange(objectModification)) {
			return true;
		} else if (isCatalogPermsCreationChange(objectModification)) {
			return true;
		} else if (isCatalogNamesChange(objectModification)) {
			return true;
		} else if (isAcroFormDictionaryChange(objectModification)) {
			return true;
		} else if (isFontCreationChange(objectModification)) {
			return true;
		}
		return false;
	}

	private static boolean isFieldFilled(ObjectModification objectModification) {
		String key = objectModification.getObjectTree().getLastKey();
		String parentKey = getParentKey(objectModification);
		if (PAdESConstants.VALUE_NAME.equals(key) && isAnnotsKey(parentKey)) {
			return true;
		} else if (isAnnotsKey(key)) {
			Object addedObject = objectModification.getFinalObject();
			if (addedObject instanceof PdfDict && isValueChange((PdfDict) addedObject)) {
				return true;
			}
			return false;
		}
		return false;
	}

	private static boolean isValueChange(PdfDict pdfDict) {
		final PdfDict vDict = pdfDict.getAsDict(PAdESConstants.VALUE_NAME);
		if (vDict != null) {
			return true;
		}
		return false;
	}

	private static boolean isAnnotsKey(String key) {
		return PAdESConstants.ANNOTS_NAME.equals(key) || PAdESConstants.FIELDS_NAME.equals(key) ||
				PAdESConstants.PARENT_NAME.equals(key);
	}

	private static boolean isAnnotsFill(ObjectModification objectModification) {
		String lastKey = objectModification.getObjectTree().getLastKey();
		String parentKey = getParentKey(objectModification);
		if (isAnnotsKey(lastKey) || isAnnotsKey(parentKey)) {
			return PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType());
		}
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		for (String key : keyChain) {
			if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) && isAnnotsKey(key)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isFieldAppearanceCreationChange(ObjectModification objectModification) {
		boolean appearanceDictChangeFound = false;
		boolean annotChangeFound = false;
		if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType())) {
			for (String chainKey : objectModification.getObjectTree().getKeyChain()) {
				if (isAnnotsKey(chainKey)) {
					annotChangeFound = true;
				} else if (PAdESConstants.APPEARANCE_DICTIONARY_NAME.equals(chainKey)) {
					appearanceDictChangeFound = true;
				}
			}
		}
		return appearanceDictChangeFound && annotChangeFound;
	}

	private static boolean isCatalogVersionChange(ObjectModification objectModification) {
		String key = objectModification.getObjectTree().getLastKey();
		String parentKey = getParentKey(objectModification);
		if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
				PAdESConstants.VERSION_NAME.equals(key) && PAdESConstants.CATALOG_NAME.equals(parentKey)) {
			return true;
		}
		return false;
	}

	private static boolean isCatalogExtensionsChange(ObjectModification objectModification) {
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		for (String key : keyChain) {
			if (PAdESConstants.EXTENSIONS_NAME.equals(key)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isCatalogPieceInfoChange(ObjectModification objectModification) {
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		for (String key : keyChain) {
			if (PAdESConstants.PIECE_INFO_NAME.equals(key)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isCatalogPermsCreationChange(ObjectModification objectModification) {
		String key = objectModification.getObjectTree().getLastKey();
		if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) &&
				PAdESConstants.PERMS_NAME.equals(key)) {
			return true;
		}
		return false;
	}

	private static boolean isCatalogNamesChange(ObjectModification objectModification) {
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		for (String key : keyChain) {
			if (PAdESConstants.NAMES_NAME.equals(key)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isMetaDataChange(ObjectModification objectModification) {
		String key = objectModification.getObjectTree().getLastKey();
		String parentKey = getParentKey(objectModification);
		if (PAdESConstants.METADATA_NAME.equals(key) || PAdESConstants.METADATA_NAME.equals(parentKey)) {
			return true;
		}
		return false;
	}

	private static boolean isAcroFormDictionaryChange(ObjectModification objectModification) {
		boolean containsAcroForm = false;
		boolean containsResourseDict = false;
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		for (String key : keyChain) {
			if (PAdESConstants.ACRO_FORM_NAME.equals(key)) {
				containsAcroForm = true;
			} else if (PAdESConstants.DOCUMENT_APPEARANCE_NAME.equals(key) ||
					PAdESConstants.DOCUMENT_RESOURCES_NAME.equals(key) || PAdESConstants.SIG_FLAGS_NAME.equals(key)) {
				containsResourseDict = true;
			}
		}
		return containsAcroForm && containsResourseDict;
	}

	private static boolean isFontCreationChange(ObjectModification objectModification) {
		String key = objectModification.getObjectTree().getLastKey();
		String parentKey = getParentKey(objectModification);
		if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) &&
				(PAdESConstants.FONT_NAME.equals(key) || PAdESConstants.FONT_NAME.equals(parentKey))) {
			return true;
		}
		return false;
	}

	private static String getParentKey(ObjectModification objectModification) {
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		if (keyChain.size() > 1) {
			return keyChain.get(keyChain.size() - 2);
		}
		return null;
	}

	private static boolean isAnnotCreationChange(ObjectModification objectModification) {
		if (isAnnotsCreation(objectModification)) {
			return true;
		}
		return false;
	}

	private static boolean isAnnotsCreation(ObjectModification objectModification) {
		String lastKey = objectModification.getObjectTree().getLastKey();
		String parentKey = getParentKey(objectModification);
		return isAnnotsKey(lastKey) || isAnnotsKey(parentKey);
	}

}
