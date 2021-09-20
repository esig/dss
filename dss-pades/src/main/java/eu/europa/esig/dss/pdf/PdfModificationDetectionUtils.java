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
				if (finalObject instanceof PdfDict || finalObject instanceof PdfArray) {
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
			if (finalObject instanceof PdfDict || finalObject instanceof PdfArray) {
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
			if (signedObject instanceof PdfDict || signedObject instanceof PdfArray) {
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
			LOG.debug("Unable to compare underlying stream binaries. Reason : {}", e.getMessage());
			return DSSUtils.EMPTY_BYTE_ARRAY;
		}
	}

}
