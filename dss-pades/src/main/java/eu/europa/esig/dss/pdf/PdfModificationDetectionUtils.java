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
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

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

	public static List<ObjectModification> getModificationsList(final PdfDocumentReader signedRevisionReader,
														  final PdfDocumentReader finalRevisionReader) {
		final List<ObjectModification> modifications = new ArrayList<>();

		final PdfDict signedCatalogDict = signedRevisionReader.getCatalogDictionary();
		final PdfDict finalCatalogDict = finalRevisionReader.getCatalogDictionary();
		compareDictsRecursively(modifications, new ArrayList<>(), new PdfObjectTree(PAdESConstants.CATALOG_NAME),
				signedCatalogDict, finalCatalogDict);

		return modifications;
	}

	private static void compareDictsRecursively(List<ObjectModification> modifications, List<Long> processedObjects,
												PdfObjectTree objectTree, PdfDict signedDict, PdfDict finalDict) {
		final String[] signedRevKeys = signedDict.list();
		final String[] finalRevKeys = finalDict.list();
		for (String key : signedRevKeys) {
			final PdfObjectTree currentObjectTree = objectTree.copy();
			Long objectNumber = signedDict.getObjectNumber(key);
			if (!processedObjects.contains(objectNumber)) {
				currentObjectTree.addKey(key);
				if (objectNumber != null) {
					processedObjects.add(objectNumber);
					currentObjectTree.addReference(objectNumber);
				}
				compareObjectsRecursively(modifications, processedObjects,
						currentObjectTree, signedDict.getObject(key), finalDict.getObject(key));
			}
		}
		List<String> signedRevKeyList = Arrays.asList(signedRevKeys);
		for (String key : finalRevKeys) {
			final PdfObjectTree currentObjectTree = objectTree.copy();
			if (!signedRevKeyList.contains(key)) {
				currentObjectTree.addKey(key);
				LOG.warn("Added entry with key '{}'.", currentObjectTree);
				modifications.add(ObjectModification.create(currentObjectTree, finalDict));
			}
		}
	}

	private static void compareObjectsRecursively(List<ObjectModification> modifications, List<Long> processedObjects,
												  PdfObjectTree objectTree, Object signedObject, Object finalObject) {
		if (signedObject == null && finalObject != null) {
			LOG.warn("Added entry with key '{}'.", objectTree);
			modifications.add(ObjectModification.create(objectTree, finalObject));

		} else if (signedObject != null && finalObject == null) {
			LOG.warn("Deleted entry with key '{}'.", objectTree);
			modifications.add(ObjectModification.delete(objectTree, signedObject));

		} else if (signedObject != null && finalObject != null) {
			if (signedObject instanceof PdfDict && finalObject instanceof PdfDict) {
				compareDictsRecursively(modifications, processedObjects, objectTree, (PdfDict) signedObject, (PdfDict) finalObject);

			} else if (signedObject instanceof PdfArray && finalObject instanceof PdfArray) {
				PdfArray signedArray = (PdfArray) signedObject;
				PdfArray finalArray = (PdfArray) finalObject;
				for (int i = 0; i < signedArray.size(); i++) {
					final PdfObjectTree currentObjectTree = objectTree.copy();
					Long objectNumber = signedArray.getObjectNumber(i);
					if (!processedObjects.contains(objectNumber)) {
						Object signedRevObject = signedArray.getObject(i);
						Object finalRevObject = null;
						if (finalArray.size() > i) {
							finalRevObject = finalArray.getObject(i);
						}
						if (objectNumber != null) {
							processedObjects.add(objectNumber);
							currentObjectTree.addReference(objectNumber);
						}
						compareObjectsRecursively(modifications, processedObjects, currentObjectTree, signedRevObject, finalRevObject);
					}
				}
				for (int i = 0; i < finalArray.size(); i++) {
					final PdfObjectTree currentObjectTree = objectTree.copy();
					Long objectNumber = finalArray.getObjectNumber(i);
					if (!processedObjects.contains(objectNumber)) {
						Object signedRevObject = null;
						Object finalRevObject = finalArray.getObject(i);
						if (signedArray.size() > i) {
							signedRevObject = signedArray.getObject(i);
						}
						if (objectNumber != null) {
							processedObjects.add(objectNumber);
							currentObjectTree.addReference(objectNumber);
						}
						compareObjectsRecursively(modifications, processedObjects, currentObjectTree, signedRevObject, finalRevObject);
					}
				}

			} else if (signedObject instanceof String && finalObject instanceof String) {
				if (!signedObject.equals(finalObject)) {
					LOG.warn("Object changed with key '{}'.", objectTree);
					modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
				}

			} else if (signedObject instanceof Number && finalObject instanceof Number) {
				if (!signedObject.equals(finalObject)) {
					LOG.warn("Object changed with key '{}'.", objectTree);
					modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
				}

			} else if (signedObject instanceof Boolean && finalObject instanceof Boolean) {
				if (!signedObject.equals(finalObject)) {
					LOG.warn("Object changed with key '{}'.", objectTree);
					modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
				}

			} else {
				LOG.warn("Unsupported objects found with key '{}' of types '{}' and '{}'",
						objectTree, signedObject.getClass(), finalObject.getClass());
				modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
			}
		}
	}

	public static PdfObjectModifications categorizeObjectModifications(List<ObjectModification> objectModificationList) {
		final PdfObjectModifications objectModifications = new PdfObjectModifications();

		for (ObjectModification objectModification : objectModificationList) {
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

	private static boolean isSecureChange(ObjectModification objectModification) {
		if (isDSSDictionaryChange(objectModification)) {
			return true;
		} else if (isDocTimeStampAdded(objectModification)) {
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
		if (PAdESConstants.ANNOTS_NAME.equals(key) || PAdESConstants.FIELDS_NAME.equals(key)) {
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

	private static boolean isFormFillAndSignatureCreationChange(ObjectModification objectModification) {
		if (isFieldFilled(objectModification)) {
			return true;
		} else if (isAnnotsFill(objectModification)) {
			return true;
		} else if (isMetaDataChange(objectModification)) {
			return true;
		}
		return false;
	}

	private static boolean isFieldFilled(ObjectModification objectModification) {
		String key = objectModification.getObjectTree().getLastKey();
		if (PAdESConstants.ANNOTS_NAME.equals(key) || PAdESConstants.FIELDS_NAME.equals(key)) {
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

	private static boolean isAnnotsFill(ObjectModification objectModification) {
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		if (keyChain.size() > 2 && PAdESConstants.ANNOTS_NAME.equals(keyChain.get(keyChain.size() - 2))) {
			return true;
		}
		return false;
	}

	private static boolean isMetaDataChange(ObjectModification objectModification) {
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		if (keyChain.size() > 2 && PAdESConstants.METADATA_NAME.equals(keyChain.get(keyChain.size() - 2))) {
			return true;
		}
		return false;
	}

	private static boolean isAnnotCreationChange(ObjectModification objectModification) {
		if (isAnnotsCreation(objectModification)) {
			return true;
		} else if (isAcroFormValueAddition(objectModification)) {
			return true;
		}
		return false;
	}

	private static boolean isAnnotsCreation(ObjectModification objectModification) {
		String lastKey = objectModification.getObjectTree().getLastKey();
		if (PAdESConstants.ANNOTS_NAME.equals(lastKey)) {
			return true;
		}
		return false;
	}

	private static boolean isAcroFormValueAddition(ObjectModification objectModification) {
		List<String> keyChain = objectModification.getObjectTree().getKeyChain();
		if (PdfObjectModificationType.CREATION.equals(objectModification.getType()) &&
				keyChain.size() > 2 && PAdESConstants.ACRO_FORM_NAME.equals(keyChain.get(keyChain.size() - 2))) {
			return true;
		}
		return false;
	}

}
